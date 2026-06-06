"""Orquestrador de captura: coleta, normalização, sanitização completa e persistência.

Pipeline garantido:
  coleta → normalização → sanitização completa → FailureRecord → arquivos → persistência

Nenhum storage recebe dados brutos potencialmente sensíveis.
"""

from __future__ import annotations

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

        # 1. Coleta bruta
        raw_exception_info = build_exception_info(exception)
        frames = build_frames(exception, self.config, self._redactor)
        runtime_info = build_runtime_info()

        context_data = {**current_context(), **(ctx.metadata or {})}
        raw_breadcrumbs = current_breadcrumbs()[: self.config.max_breadcrumbs]

        raw_arguments = ctx.arguments or {}
        raw_extensions, collector_errors = self.collectors.run(exception, ctx, self.config)

        # 2. Sanitização completa antes de qualquer persistência
        exception_info = self._redactor.redact_exception_info(raw_exception_info)
        arguments = self._redact_dict(raw_arguments)
        metadata = self._redact_dict(context_data)
        breadcrumbs = tuple(self._redactor.redact_breadcrumb(b) for b in raw_breadcrumbs)
        extensions = self._redact_dict(raw_extensions)

        # 3. Fingerprint sobre dados já sanitizados
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
            metadata=metadata,
            breadcrumbs=breadcrumbs,
            collector_errors=tuple({k: str(v) for k, v in e.items()} for e in collector_errors),
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

        # Traceback textual sanitizado
        tb_lines = _traceback.format_exception(type(exception), exception, exception.__traceback__)
        raw_tb = "".join(tb_lines)
        extra["traceback_text"] = self._redactor.redact_text(raw_tb)

        # Canonical da fingerprint também sanitizada (já usa dados sanitizados, mas aplicamos novamente por garantia)
        sanitized_canonical = self._sanitize_fingerprint_canonical(fingerprint_canonical)
        extra["fingerprint_canonical"] = sanitized_canonical

        if (
            record.callable_info
            and record.callable_info.replayable
            and record.replay_arguments is not None
        ):
            extra["replay"] = self._build_replay(record)

        return extra

    def _sanitize_fingerprint_canonical(self, canonical: dict[str, Any]) -> dict[str, Any]:
        """Garante que nenhum segredo sobreviva na representação canônica armazenada."""
        result: dict[str, Any] = {}
        for k, v in canonical.items():
            if isinstance(v, str):
                result[k] = self._redactor.redact_text(v)
            elif isinstance(v, list):
                result[k] = [
                    {
                        ik: self._redactor.redact_text(iv) if isinstance(iv, str) else iv
                        for ik, iv in item.items()
                    }
                    if isinstance(item, dict)
                    else item
                    for item in v
                ]
            else:
                result[k] = v
        return result

    def _build_replay(self, record: FailureRecord) -> dict[str, Any]:
        ci = record.callable_info
        assert ci is not None

        encoded_args = self.serializer.encode(list(record.replay_arguments or ()))
        encoded_kwargs = self.serializer.encode(record.replay_keyword_arguments or {})

        redacted_args = self._redactor.redact_encoded(encoded_args)
        redacted_kwargs = self._redactor.redact_encoded(encoded_kwargs)

        return {
            "module": ci.module,
            "qualname": ci.qualname,
            "arguments": redacted_args,
            "keyword_arguments": redacted_kwargs,
        }
