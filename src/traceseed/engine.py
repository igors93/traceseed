"""Orquestrador de captura: coleta, redação, fingerprint e persistência."""

from __future__ import annotations

import sys
import traceback as _traceback
import uuid
from typing import Any

from .collectors import (
    CollectorRegistry,
    build_exception_info,
    build_frames,
    build_runtime_info,
)
from .config import TraceSeedConfig
from .context import current_breadcrumbs, current_context
from .fingerprint import Fingerprinter
from .models import (
    CaptureContext,
    CaptureResult,
    CallableInfo,
    FailureRecord,
)
from .redaction import Redactor
from .serialization import SafeSerializer
from .storage.base import StoredFailure

_VERSION = "0.1.0"


class CaptureEngine:
    def __init__(
        self,
        config: TraceSeedConfig,
        collectors: CollectorRegistry | None = None,
        storage: Any = None,
        serializer: SafeSerializer | None = None,
    ) -> None:
        self.config = config
        self.collectors = collectors or CollectorRegistry()
        self.storage = storage
        self.serializer = serializer or SafeSerializer(config)
        self._redactor = Redactor(config)
        self._fingerprinter = Fingerprinter(config)

    def capture(
        self,
        exception: BaseException,
        ctx: CaptureContext,
    ) -> CaptureResult:
        incident_id = str(uuid.uuid4())
        created_at = FailureRecord.utc_now()

        exception_info = build_exception_info(exception)
        frames = build_frames(exception, self.config, self._redactor)
        runtime_info = build_runtime_info()

        context_data = {**current_context(), **(ctx.metadata or {})}
        breadcrumbs = current_breadcrumbs()[: self.config.max_breadcrumbs]

        arguments = self._redact_dict(ctx.arguments or {})

        extensions, collector_errors = self.collectors.run(exception, ctx, self.config)

        fingerprint = self._fingerprinter.generate(exception_info, frames)

        callable_info = ctx.callable_info
        replay_arguments = ctx.replay_arguments
        replay_keyword_arguments = ctx.replay_keyword_arguments

        record = FailureRecord(
            incident_id=incident_id,
            fingerprint=fingerprint.value,
            created_at=created_at,
            operation=ctx.operation,
            exception=exception_info,
            frames=frames,
            runtime=runtime_info,
            arguments=arguments,
            metadata=context_data,
            breadcrumbs=breadcrumbs,
            collector_errors=tuple(
                {k: str(v) for k, v in e.items()} for e in collector_errors
            ),
            extensions=extensions,
            callable_info=callable_info,
            replay_arguments=replay_arguments,
            replay_keyword_arguments=replay_keyword_arguments,
            format_version=1,
            library_version=_VERSION,
        )

        extra = self._build_extra(exception, record, fingerprint.canonical)

        stored, capture_error = self._save_safe(record, extra)
        return CaptureResult(
            record=record,
            location=stored.location if stored else None,
            storage_name=stored.storage_name if stored else "none",
            capture_error=capture_error,
        )

    def _save_safe(
        self, record: FailureRecord, extra: dict[str, Any]
    ) -> tuple[StoredFailure | None, str | None]:
        if self.storage is None:
            return None, None
        try:
            return self.storage.save(record, extra), None
        except Exception as exc:
            return None, str(exc)

    def _redact_dict(self, data: dict[str, Any]) -> dict[str, Any]:
        return {k: self._redactor.redact(v, key=k) for k, v in data.items()}

    def _build_extra(
        self,
        exception: BaseException,
        record: FailureRecord,
        fingerprint_canonical: dict[str, Any],
    ) -> dict[str, Any]:
        extra: dict[str, Any] = {}

        tb_lines = _traceback.format_exception(type(exception), exception, exception.__traceback__)
        extra["traceback_text"] = "".join(tb_lines)
        extra["fingerprint_canonical"] = fingerprint_canonical

        if record.callable_info and record.callable_info.replayable and record.replay_arguments is not None:
            extra["replay"] = self._build_replay(record)

        return extra

    def _build_replay(self, record: FailureRecord) -> dict[str, Any]:
        ci = record.callable_info
        assert ci is not None

        encoded_args = self.serializer.encode(list(record.replay_arguments))
        encoded_kwargs = self.serializer.encode(record.replay_keyword_arguments or {})

        redacted_args = self._redactor.redact_encoded(encoded_args)
        redacted_kwargs = self._redactor.redact_encoded(encoded_kwargs)

        return {
            "module": ci.module,
            "qualname": ci.qualname,
            "arguments": redacted_args,
            "keyword_arguments": redacted_kwargs,
        }
