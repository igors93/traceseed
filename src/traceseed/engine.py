"""Orquestrador de captura: coleta, normalização, sanitização completa e persistência.

Pipeline garantido:
  coleta → normalização → sanitização completa → FailureRecord → arquivos → persistência

Nenhum storage recebe dados brutos potencialmente sensíveis.
Nenhum argumento bruto de replay é persistido em FailureRecord.

Fronteira de falhas internas: qualquer exceção dentro do pipeline TraceSeed é
contida e reportada como capture_error — nunca substitui a exceção original.
"""

from __future__ import annotations

import json
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
    ExceptionInfo,
    FailureRecord,
)
from .redaction import CIRCULAR_REFERENCE, MAX_DEPTH, REDACTED, TRUNCATED, Redactor
from .serialization import SafeSerializer
from .storage.base import StoredFailure

_VERSION = "0.1.0"

# Marcadores que tornam um replay não reproduzível
_UNSAFE_REPLAY_ENCODED_TYPES = frozenset(
    {"max_depth", "circular_reference", "unresolved", "codec_error"}
)
_UNSAFE_REPLAY_MARKERS = (REDACTED, TRUNCATED, MAX_DEPTH, CIRCULAR_REFERENCE)
_TYPE_MARKER = "__traceseed_type__"


def _has_unsafe_encoded(value: Any, _depth: int = 0) -> bool:
    """Verifica recursivamente se algum valor codificado foi redigido ou é irresolvível."""
    if _depth > 50:
        return True
    if isinstance(value, str):
        return value in _UNSAFE_REPLAY_MARKERS
    if isinstance(value, list):
        return any(_has_unsafe_encoded(item, _depth + 1) for item in value)
    if isinstance(value, dict):
        kind = value.get(_TYPE_MARKER)
        if kind in _UNSAFE_REPLAY_ENCODED_TYPES:
            return True
        return any(_has_unsafe_encoded(v, _depth + 1) for v in value.values())
    return False


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
        """Captura com fronteira global: nunca lança exceção para o chamador."""
        try:
            return self._capture_impl(exception, ctx)
        except Exception as internal:
            try:
                err_msg = f"{type(internal).__name__}: {internal}"
            except Exception:
                err_msg = type(internal).__name__
            return CaptureResult(
                record=self._minimal_record(exception),
                location=None,
                storage_name="none",
                capture_error=f"traceseed internal error: {err_msg}",
            )

    def _capture_impl(
        self,
        exception: BaseException,
        ctx: CaptureContext,
    ) -> CaptureResult:
        incident_id = str(uuid.uuid4())
        created_at = FailureRecord.utc_now()

        # 1. Coleta bruta
        raw_exception_info = build_exception_info(
            exception,
            max_depth=self.config.max_exception_depth,
            max_children=self.config.max_exception_children,
        )
        frames = build_frames(exception, self.config, self._redactor)
        runtime_info = build_runtime_info(self.config)

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

        # Sanitiza mensagens de erro dos coletores (podem conter segredos)
        sanitized_collector_errors = tuple(
            {
                "collector": e.get("collector", ""),
                "error": e.get("error", ""),
                "message": self._redactor.redact_text(
                    e.get("message", "")[: self.config.max_value_length]
                ),
            }
            for e in collector_errors
        )

        # Sanitiza operation (pode conter segredos se derivada de dados de usuário)
        operation = ctx.operation
        if operation is not None:
            operation = self._redactor.redact_text(
                str(operation)[: self.config.max_operation_length]
            )

        # 3. Fingerprint sobre dados já sanitizados
        fingerprint = self._fingerprinter.generate(exception_info, frames)

        callable_info = ctx.callable_info

        record = FailureRecord(
            incident_id=incident_id,
            fingerprint=fingerprint.value,
            created_at=created_at,
            operation=operation,
            exception=exception_info,
            frames=frames,
            runtime=runtime_info,
            arguments=arguments,
            metadata=metadata,
            breadcrumbs=breadcrumbs,
            collector_errors=sanitized_collector_errors,
            extensions=extensions,
            callable_info=callable_info,
            format_version=1,
            library_version=_VERSION,
        )

        extra = self._build_extra(exception, record, fingerprint.canonical, ctx)

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
            try:
                msg = str(exc)
            except Exception:
                msg = type(exc).__name__
            return None, msg

    def _redact_dict(self, data: dict[str, Any]) -> dict[str, Any]:
        return {k: self._redactor.redact(v, key=k) for k, v in data.items()}

    def _build_extra(
        self,
        exception: BaseException,
        record: FailureRecord,
        fingerprint_canonical: dict[str, Any],
        ctx: CaptureContext,
    ) -> dict[str, Any]:
        extra: dict[str, Any] = {}

        # Traceback textual sanitizado e limitado
        tb_lines = _traceback.format_exception(type(exception), exception, exception.__traceback__)
        raw_tb = "".join(tb_lines)
        sanitized_tb = self._redactor.redact_text(raw_tb)
        if len(sanitized_tb) > self.config.max_traceback_text_length:
            sanitized_tb = (
                sanitized_tb[: self.config.max_traceback_text_length] + "\n...[TRUNCATED]"
            )
        extra["traceback_text"] = sanitized_tb

        # Canonical da fingerprint sanitizada
        sanitized_canonical = self._sanitize_fingerprint_canonical(fingerprint_canonical)
        extra["fingerprint_canonical"] = sanitized_canonical

        # Replay: construído apenas se callable é importável, replayable=True,
        # hashes estão habilitados E argumentos brutos foram fornecidos.
        if (
            record.callable_info is not None
            and record.callable_info.replayable
            and ctx.replay_arguments is not None
            and self.config.include_package_hashes
        ):
            replay = self._build_replay(ctx)
            if replay is not None:
                extra["replay"] = replay

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

    def _build_replay(self, ctx: CaptureContext) -> dict[str, Any] | None:
        """Constrói payload de replay sanitizado.

        Retorna None se os argumentos contiverem valores redigidos, truncados
        ou irresolvíveis — replay com dados alterados nunca deve ser executado.
        """
        ci = ctx.callable_info
        if ci is None:
            return None

        encoded_args = self.serializer.encode(list(ctx.replay_arguments or ()))
        encoded_kwargs = self.serializer.encode(ctx.replay_keyword_arguments or {})

        redacted_args = self._redactor.redact_encoded(encoded_args)
        redacted_kwargs = self._redactor.redact_encoded(encoded_kwargs)

        # Verifica se algum argumento foi alterado — nesse caso replay não é seguro
        if _has_unsafe_encoded(redacted_args) or _has_unsafe_encoded(redacted_kwargs):
            return {
                "replayable": False,
                "reason": "arguments were redacted, truncated, or unresolvable",
            }

        payload = {
            "replayable": True,
            "module": ci.module,
            "qualname": ci.qualname,
            "arguments": redacted_args,
            "keyword_arguments": redacted_kwargs,
        }

        # Limita tamanho total do payload
        try:
            payload_text = json.dumps(payload)
        except Exception:
            return {"replayable": False, "reason": "serialization failed"}
        if len(payload_text.encode()) > self.config.max_replay_payload_size:
            return {"replayable": False, "reason": "payload too large"}

        return payload

    def _minimal_record(self, exception: BaseException) -> FailureRecord:
        """Cria FailureRecord mínimo para o caso de falha interna do engine."""
        try:
            module = type(exception).__module__
            type_name = type(exception).__qualname__
        except Exception:
            module = "unknown"
            type_name = "unknown"
        exc_info = ExceptionInfo(
            module=module,
            type_name=type_name,
            message="",
            representation="",
        )
        return FailureRecord(
            incident_id=str(uuid.uuid4()),
            fingerprint="0" * 32,
            created_at=FailureRecord.utc_now(),
            operation=None,
            exception=exc_info,
            frames=(),
            runtime=None,
            arguments={},
            metadata={},
            breadcrumbs=(),
        )
