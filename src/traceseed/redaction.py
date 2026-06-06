"""Recursive sanitization for potentially sensitive diagnostic data."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import fields, is_dataclass
from typing import Any

from .config import TraceSeedConfig
from .models import Breadcrumb, CallableInfo, ExceptionInfo, FrameInfo, RuntimeInfo

REDACTED = "[REDACTED]"
TRUNCATED = "[TRUNCATED]"
MAX_DEPTH = "[MAX_DEPTH]"
CIRCULAR_REFERENCE = "[CIRCULAR_REFERENCE]"
_TYPE_MARKER = "__traceseed_type__"


class Redactor:
    """Remove configured secrets while bounding traversal and representation work."""

    def __init__(
        self,
        config: TraceSeedConfig,
        custom: Callable[[str | None, Any], Any] | None = None,
    ) -> None:
        self.config = config
        self.sensitive_fields = set(config.redact_fields)
        self.patterns = tuple(re.compile(pattern) for pattern in config.redact_patterns)
        self.custom = custom

    def redact(self, value: Any, key: str | None = None) -> Any:
        return self._redact(value, key=key, depth=0, seen=set())

    def _redact(
        self,
        value: Any,
        *,
        key: str | None,
        depth: int,
        seen: set[int],
    ) -> Any:
        if key is not None and self._is_sensitive_key(key):
            return REDACTED
        if self.custom is not None:
            try:
                replacement = self.custom(key, value)
            except Exception:
                replacement = value
            if replacement is not value:
                return replacement
        if depth >= self.config.max_depth:
            return MAX_DEPTH
        if value is None or isinstance(value, (bool, int, float)):
            return value
        if isinstance(value, str):
            return self.redact_text(value)
        if isinstance(value, (bytes, bytearray, memoryview)):
            return self.redact_text(bytes(value).decode("utf-8", errors="replace"))

        track = isinstance(value, (Mapping, list, tuple, set, frozenset)) or (
            is_dataclass(value) and not isinstance(value, type)
        )
        identity = id(value)
        if track:
            if identity in seen:
                return CIRCULAR_REFERENCE
            seen.add(identity)
        try:
            if isinstance(value, Mapping):
                output: dict[str, Any] = {}
                for index, pair in enumerate(value.items()):
                    if index >= self.config.max_collection_items:
                        output[TRUNCATED] = True
                        break
                    raw_key, raw_value = pair
                    key_text = self._safe_key(raw_key)
                    output[key_text] = self._redact(
                        raw_value,
                        key=key_text,
                        depth=depth + 1,
                        seen=seen,
                    )
                return output
            if is_dataclass(value) and not isinstance(value, type):
                output = {}
                all_fields = fields(value)
                for item in all_fields[: self.config.max_collection_items]:
                    try:
                        item_value = getattr(value, item.name)
                    except Exception:
                        item_value = "[ATTRIBUTE_READ_FAILED]"
                    output[item.name] = self._redact(
                        item_value,
                        key=item.name,
                        depth=depth + 1,
                        seen=seen,
                    )
                if len(all_fields) > self.config.max_collection_items:
                    output[TRUNCATED] = True
                return output
            if isinstance(value, (list, tuple, set, frozenset)):
                try:
                    sequence = list(value)
                except Exception:
                    return self.redact_text(self._safe_repr(value))
                result = [
                    self._redact(item, key=None, depth=depth + 1, seen=seen)
                    for item in sequence[: self.config.max_collection_items]
                ]
                if len(sequence) > self.config.max_collection_items:
                    result.append(TRUNCATED)
                return result
            return self.redact_text(self._safe_repr(value))
        finally:
            if track:
                seen.discard(identity)

    def redact_encoded(self, value: Any, key: str | None = None) -> Any:
        return self._redact_encoded(value, key=key, depth=0)

    def _redact_encoded(self, value: Any, *, key: str | None, depth: int) -> Any:
        if key is not None and self._is_sensitive_key(key):
            return REDACTED
        if depth >= self.config.max_depth * 4:
            return {_TYPE_MARKER: "max_depth"}
        if value is None or isinstance(value, (bool, int, float)):
            return value
        if isinstance(value, str):
            return self.redact_text(value)
        if isinstance(value, list):
            result = [
                self._redact_encoded(item, key=None, depth=depth + 1)
                for item in value[: self.config.max_collection_items]
            ]
            if len(value) > self.config.max_collection_items:
                result.append(TRUNCATED)
            return result
        if not isinstance(value, dict):
            return self._redact(value, key=key, depth=depth, seen=set())

        kind = value.get(_TYPE_MARKER)
        if isinstance(kind, str):
            output: dict[str, Any] = {}
            for raw_key, raw_value in value.items():
                key_text = self._safe_key(raw_key)
                if key_text == "items" and isinstance(raw_value, list):
                    if kind == "dict":
                        sanitized_pairs = []
                        for pair in raw_value:
                            if not isinstance(pair, list) or len(pair) != 2:
                                sanitized_pairs.append(
                                    self._redact_encoded(pair, key=None, depth=depth + 1)
                                )
                                continue
                            encoded_key, encoded_value = pair
                            plain_key = encoded_key if isinstance(encoded_key, str) else None
                            sanitized_pairs.append(
                                [
                                    self._redact_encoded(encoded_key, key=None, depth=depth + 1),
                                    self._redact_encoded(
                                        encoded_value,
                                        key=plain_key,
                                        depth=depth + 1,
                                    ),
                                ]
                            )
                        output[key_text] = sanitized_pairs
                    else:
                        output[key_text] = [
                            self._redact_encoded(item, key=None, depth=depth + 1)
                            for item in raw_value
                        ]
                elif key_text == "fields" and isinstance(raw_value, dict):
                    output[key_text] = {
                        self._safe_key(field_name): self._redact_encoded(
                            field_value,
                            key=self._safe_key(field_name),
                            depth=depth + 1,
                        )
                        for field_name, field_value in raw_value.items()
                    }
                elif key_text in {_TYPE_MARKER, "module", "class", "name", "encoding"}:
                    output[key_text] = (
                        self.redact_text(raw_value)
                        if isinstance(raw_value, str) and key_text not in {_TYPE_MARKER, "encoding"}
                        else raw_value
                    )
                else:
                    nested_key = key if key_text == "value" else key_text
                    output[key_text] = self._redact_encoded(
                        raw_value,
                        key=nested_key,
                        depth=depth + 1,
                    )
            return output

        plain_output: dict[str, Any] = {}
        for raw_key, raw_value in value.items():
            key_text = self._safe_key(raw_key)
            plain_output[key_text] = self._redact_encoded(
                raw_value,
                key=key_text,
                depth=depth + 1,
            )
        return plain_output

    def redact_exception_info(
        self,
        info: ExceptionInfo | None,
        _depth: int = 0,
        _seen: frozenset[int] | None = None,
    ) -> ExceptionInfo | None:
        if info is None:
            return None
        seen = _seen or frozenset()
        if _depth >= self.config.max_exception_depth or id(info) in seen:
            return ExceptionInfo(
                module=self.redact_text(info.module),
                type_name=self.redact_text(info.type_name),
                message=MAX_DEPTH,
                representation=MAX_DEPTH,
            )
        seen = seen | {id(info)}
        return ExceptionInfo(
            module=self.redact_text(info.module),
            type_name=self.redact_text(info.type_name),
            message=self.redact_text(info.message),
            representation=self.redact_text(info.representation),
            cause=self.redact_exception_info(info.cause, _depth + 1, seen),
            context=self.redact_exception_info(info.context, _depth + 1, seen),
            suppress_context=info.suppress_context,
            notes=tuple(self.redact_text(note) for note in info.notes),
            children=tuple(
                child
                for item in info.children[: self.config.max_exception_children]
                if (child := self.redact_exception_info(item, _depth + 1, seen)) is not None
            ),
        )

    def redact_frame(self, frame: FrameInfo) -> FrameInfo:
        return FrameInfo(
            filename=self.redact_text(frame.filename),
            function=self.redact_text(frame.function),
            line_number=frame.line_number,
            module=self.redact_text(frame.module) if frame.module is not None else None,
            source_line=(
                self.redact_text(frame.source_line) if frame.source_line is not None else None
            ),
            locals=self.redact(frame.locals),
        )

    def redact_runtime(self, runtime: RuntimeInfo | None) -> RuntimeInfo | None:
        if runtime is None:
            return None
        return RuntimeInfo(
            python_version=self.redact_text(runtime.python_version),
            implementation=self.redact_text(runtime.implementation),
            operating_system=self.redact_text(runtime.operating_system),
            platform=self.redact_text(runtime.platform),
            architecture=self.redact_text(runtime.architecture),
            executable=self.redact_text(runtime.executable),
            cwd=self.redact_text(runtime.cwd),
            process_id=runtime.process_id,
            thread_name=self.redact_text(runtime.thread_name),
            argv=tuple(self.redact_text(value) for value in runtime.argv),
        )

    def redact_breadcrumb(self, value: Breadcrumb) -> Breadcrumb:
        return Breadcrumb(
            timestamp=value.timestamp,
            category=self.redact_text(value.category),
            message=self.redact_text(value.message),
            data={
                self._safe_key(key): self.redact(item, key=self._safe_key(key))
                for key, item in value.data.items()
            },
            level=self.redact_text(value.level),
        )

    def redact_callable_info(self, value: CallableInfo | None) -> CallableInfo | None:
        if value is None:
            return None
        return CallableInfo(
            module=self.redact_text(value.module),
            qualname=self.redact_text(value.qualname),
            replayable=value.replayable,
            reason=self.redact_text(value.reason) if value.reason is not None else None,
        )

    def _is_sensitive_key(self, key: str) -> bool:
        normalized = key.casefold().replace("-", "_").replace(" ", "_")
        return any(
            normalized == field or normalized.startswith(f"{field}_")
            for field in self.sensitive_fields
        )

    def redact_text(self, text: str) -> str:
        output = text if isinstance(text, str) else self._safe_repr(text)
        for pattern in self.patterns:
            output = pattern.sub(REDACTED, output)
        if len(output) > self.config.max_value_length:
            output = output[: self.config.max_value_length] + "…[TRUNCATED]"
        return output

    @staticmethod
    def _safe_repr(value: Any) -> str:
        try:
            return repr(value)
        except Exception as error:
            return (
                f"<unrepresentable {type(value).__module__}."
                f"{type(value).__qualname__}: {type(error).__name__}>"
            )

    @classmethod
    def _safe_key(cls, value: Any) -> str:
        if isinstance(value, str):
            return value
        try:
            return str(value)
        except Exception:
            return cls._safe_repr(value)
