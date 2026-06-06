"""Capture orchestration with sanitization before persistence."""

from __future__ import annotations

import json
import traceback as traceback_module
import uuid
from typing import Any

from .collectors import (
    CollectorRegistry,
    build_exception_info,
    build_frames,
    build_runtime_info,
    build_thread_info,
)
from .config import TraceSeedConfig
from .context import current_breadcrumbs, current_context
from .fingerprint import Fingerprinter
from .models import CaptureContext, CaptureResult, ExceptionInfo, FailureRecord
from .redaction import (
    CIRCULAR_REFERENCE,
    MAX_DEPTH,
    REDACTED,
    TRUNCATED,
    Redactor,
)
from .serialization import SafeSerializer
from .storage.base import StoredFailure

_VERSION = "0.1.0"
_TYPE_MARKER = "__traceseed_type__"
_UNSAFE_TYPES = frozenset({"max_depth", "circular_reference", "unresolved", "codec_error"})
_UNSAFE_STRINGS = (REDACTED, TRUNCATED, MAX_DEPTH, CIRCULAR_REFERENCE, "[TRUNCATED]")


def _find_replay_issue(value: Any, depth: int = 0) -> str | None:
    if depth > 128:
        return "arguments exceeded the safety depth limit"
    if isinstance(value, str):
        if any(marker in value for marker in _UNSAFE_STRINGS):
            return "arguments were redacted or truncated"
        return None
    if isinstance(value, list):
        for item in value:
            issue = _find_replay_issue(item, depth + 1)
            if issue:
                return issue
        return None
    if isinstance(value, dict):
        kind = value.get(_TYPE_MARKER)
        if kind in _UNSAFE_TYPES:
            return f"arguments contain an unreconstructable {kind} value"
        if value.get("truncated") is True:
            return "arguments were truncated"
        for item in value.values():
            issue = _find_replay_issue(item, depth + 1)
            if issue:
                return issue
    return None


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
        context: CaptureContext,
    ) -> CaptureResult:
        try:
            return self._capture_impl(exception, context)
        except Exception as internal_error:
            return CaptureResult(
                record=self._minimal_record(exception),
                location=None,
                storage_name="none",
                capture_error=(
                    "traceseed internal error: "
                    f"{type(internal_error).__name__}: {_safe_text(internal_error)}"
                ),
            )

    def _capture_impl(
        self,
        exception: BaseException,
        context: CaptureContext,
    ) -> CaptureResult:
        incident_id = str(uuid.uuid4())
        created_at = FailureRecord.utc_now()

        raw_exception = build_exception_info(
            exception,
            max_depth=self.config.max_exception_depth,
            max_children=self.config.max_exception_children,
        )
        frames = tuple(
            self._redactor.redact_frame(frame)
            for frame in build_frames(exception, self.config, self._redactor)
        )
        runtime = self._redactor.redact_runtime(build_runtime_info(self.config))
        metadata_source = {**current_context(), **(context.metadata or {})}
        breadcrumbs = tuple(
            self._redactor.redact_breadcrumb(value)
            for value in current_breadcrumbs()[: self.config.max_breadcrumbs]
        )
        arguments = (
            self._redact_mapping(context.arguments or {}) if self.config.capture_arguments else {}
        )
        metadata = self._redact_mapping(metadata_source)

        raw_extensions, collector_errors = self.collectors.run(
            exception,
            context,
            self.config,
        )
        extensions = self._redact_mapping(raw_extensions)
        sanitized_errors = tuple(
            {
                "collector": self._redactor.redact_text(str(item.get("collector", ""))),
                "error": self._redactor.redact_text(str(item.get("error", ""))),
                "message": self._redactor.redact_text(str(item.get("message", ""))),
            }
            for item in collector_errors
        )

        exception_info = self._redactor.redact_exception_info(raw_exception)
        if exception_info is None:
            raise RuntimeError("exception sanitization unexpectedly returned None")
        fingerprint = self._fingerprinter.generate(exception_info, frames)
        operation = (
            self._redactor.redact_text(str(context.operation)[: self.config.max_operation_length])
            if context.operation is not None
            else None
        )
        callable_info = self._redactor.redact_callable_info(context.callable_info)

        record = FailureRecord(
            incident_id=incident_id,
            fingerprint=fingerprint.value,
            created_at=created_at,
            operation=operation,
            exception=exception_info,
            frames=frames,
            runtime=runtime,
            arguments=arguments,
            metadata=metadata,
            breadcrumbs=breadcrumbs,
            collector_errors=sanitized_errors,
            extensions=extensions,
            callable_info=callable_info,
            format_version=1,
            library_version=_VERSION,
        )
        extra = self._build_extra(exception, record, fingerprint.canonical, context)
        stored, capture_error = self._save_safe(record, extra)
        return CaptureResult(
            record=record,
            location=stored.location if stored else None,
            storage_name=stored.storage_name if stored else "none",
            capture_error=capture_error,
        )

    def _save_safe(
        self,
        record: FailureRecord,
        extra: dict[str, Any],
    ) -> tuple[StoredFailure | None, str | None]:
        if self.storage is None:
            return None, None
        try:
            stored = self.storage.save(record, extra)
            if not isinstance(stored, StoredFailure):
                raise TypeError("storage.save() must return StoredFailure")
            if not stored.location or not stored.storage_name:
                raise TypeError("StoredFailure fields must be non-empty strings")
            return stored, None
        except Exception as error:
            return None, f"{type(error).__name__}: {_safe_text(error)}"

    def _redact_mapping(self, value: dict[Any, Any]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in value.items():
            try:
                key_text = key if isinstance(key, str) else str(key)
            except Exception:
                key_text = "[UNREPRESENTABLE_KEY]"
            result[key_text] = self._redactor.redact(item, key=key_text)
        return result

    def _build_extra(
        self,
        exception: BaseException,
        record: FailureRecord,
        canonical: dict[str, Any],
        context: CaptureContext,
    ) -> dict[str, Any]:
        extra: dict[str, Any] = {}
        try:
            text = "".join(
                traceback_module.format_exception(
                    type(exception),
                    exception,
                    exception.__traceback__,
                )
            )
        except Exception:
            text = "[TRACEBACK_FORMAT_FAILED]"
        text = self._redactor.redact_text(text)
        if len(text) > self.config.max_traceback_text_length:
            text = text[: self.config.max_traceback_text_length] + "\n...[TRUNCATED]"
        extra["traceback_text"] = text
        extra["fingerprint_canonical"] = self._redactor.redact(canonical)

        threads = build_thread_info(self.config)
        if threads:
            extra["threads"] = self._redactor.redact(threads)

        callable_info = context.callable_info
        if (
            callable_info is not None
            and callable_info.replayable
            and context.replay_arguments is not None
        ):
            extra["replay"] = self._build_replay(context)
        return extra

    def _build_replay(self, context: CaptureContext) -> dict[str, Any]:
        callable_info = context.callable_info
        if callable_info is None:
            return {"replayable": False, "reason": "callable information is missing"}
        try:
            encoded_args = self.serializer.encode(list(context.replay_arguments or ()))
            encoded_kwargs = self.serializer.encode(context.replay_keyword_arguments or {})
            redacted_args = self._redactor.redact_encoded(encoded_args)
            redacted_kwargs = self._redactor.redact_encoded(encoded_kwargs)
        except Exception as error:
            return {
                "replayable": False,
                "reason": f"serialization failed: {type(error).__name__}",
            }

        issue = _find_replay_issue(redacted_args) or _find_replay_issue(redacted_kwargs)
        if issue is not None:
            return {"replayable": False, "reason": issue}

        payload = {
            "replayable": True,
            "module": self._redactor.redact_text(callable_info.module),
            "qualname": self._redactor.redact_text(callable_info.qualname),
            "arguments": redacted_args,
            "keyword_arguments": redacted_kwargs,
        }
        try:
            size = len(json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8"))
        except Exception:
            return {"replayable": False, "reason": "serialization failed"}
        if size > self.config.max_replay_payload_size:
            return {"replayable": False, "reason": "payload too large"}
        return payload

    def _minimal_record(self, exception: BaseException) -> FailureRecord:
        try:
            module = self._redactor.redact_text(type(exception).__module__)
            type_name = self._redactor.redact_text(type(exception).__qualname__)
        except Exception:
            module = "unknown"
            type_name = "unknown"
        return FailureRecord(
            incident_id=str(uuid.uuid4()),
            fingerprint="0" * 32,
            created_at=FailureRecord.utc_now(),
            operation=None,
            exception=ExceptionInfo(
                module=module,
                type_name=type_name,
                message="",
                representation="",
            ),
            frames=(),
            runtime=None,
            arguments={},
            metadata={},
            breadcrumbs=(),
        )


def _safe_text(error: BaseException) -> str:
    try:
        return str(error)
    except Exception:
        return type(error).__name__
