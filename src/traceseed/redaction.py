"""Sanitização profunda de dados sensíveis."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import is_dataclass, fields
from typing import Any, Callable

from .config import TraceSeedConfig

REDACTED = "[REDACTED]"
TRUNCATED = "[TRUNCATED]"
MAX_DEPTH = "[MAX_DEPTH]"
CIRCULAR_REFERENCE = "[CIRCULAR_REFERENCE]"
_TYPE_MARKER = "__traceseed_type__"


class Redactor:
    """Remove segredos por nome, regex e função personalizada."""

    def __init__(
        self,
        config: TraceSeedConfig,
        custom: Callable[[str | None, Any], Any] | None = None,
    ) -> None:
        self.config = config
        self.sensitive_fields = {item.casefold() for item in config.redact_fields}
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
            replacement = self.custom(key, value)
            if replacement is not value:
                return replacement
        if depth >= self.config.max_depth:
            return MAX_DEPTH
        if value is None or isinstance(value, (bool, int, float)):
            return value
        if isinstance(value, str):
            return self._redact_text(value)
        if isinstance(value, (bytes, bytearray, memoryview)):
            text = bytes(value).decode("utf-8", errors="replace")
            return self._redact_text(text)

        track_identity = isinstance(value, (Mapping, list, tuple, set, frozenset)) or is_dataclass(value)
        identity = id(value)
        if track_identity:
            if identity in seen:
                return CIRCULAR_REFERENCE
            seen.add(identity)

        try:
            if isinstance(value, Mapping):
                output: dict[str, Any] = {}
                for index, (item_key, item_value) in enumerate(value.items()):
                    if index >= self.config.max_collection_items:
                        output[TRUNCATED] = len(value) - index if hasattr(value, "__len__") else True
                        break
                    key_text = str(item_key)
                    output[key_text] = self._redact(
                        item_value,
                        key=key_text,
                        depth=depth + 1,
                        seen=seen,
                    )
                return output
            if is_dataclass(value) and not isinstance(value, type):
                return {
                    item.name: self._redact(
                        getattr(value, item.name),
                        key=item.name,
                        depth=depth + 1,
                        seen=seen,
                    )
                    for item in fields(value)[: self.config.max_collection_items]
                }
            if isinstance(value, (list, tuple, set, frozenset)):
                sequence = list(value)
                result = [
                    self._redact(item, key=None, depth=depth + 1, seen=seen)
                    for item in sequence[: self.config.max_collection_items]
                ]
                if len(sequence) > self.config.max_collection_items:
                    result.append(TRUNCATED)
                return result
            return self._redact_text(self._safe_repr(value))
        finally:
            if track_identity:
                seen.discard(identity)


    def redact_encoded(self, value: Any, key: str | None = None) -> Any:
        """Sanitiza uma árvore já produzida por ``SafeSerializer``.

        A representação tipada de dicionários usa pares em ``items``. Este
        método entende esse formato para não deixar segredos escaparem no
        payload de replay, preservando ao mesmo tempo tags de reconstrução.
        """

        return self._redact_encoded(value, key=key, depth=0)

    def _redact_encoded(self, value: Any, *, key: str | None, depth: int) -> Any:
        if key is not None and self._is_sensitive_key(key):
            return REDACTED
        if depth >= self.config.max_depth * 3:
            return {_TYPE_MARKER: "max_depth"}
        if value is None or isinstance(value, (bool, int, float)):
            return value
        if isinstance(value, str):
            return self._redact_text(value)
        if isinstance(value, list):
            return [
                self._redact_encoded(item, key=None, depth=depth + 1)
                for item in value[: self.config.max_collection_items]
            ]
        if not isinstance(value, dict):
            return self._redact(value, key=key, depth=depth, seen=set())

        kind = value.get(_TYPE_MARKER)
        if kind == "dict" and isinstance(value.get("items"), list):
            output = dict(value)
            sanitized_items = []
            for pair in value["items"][: self.config.max_collection_items]:
                if not isinstance(pair, list) or len(pair) != 2:
                    sanitized_items.append(
                        self._redact_encoded(pair, key=None, depth=depth + 1)
                    )
                    continue
                encoded_key, encoded_value = pair
                plain_key = encoded_key if isinstance(encoded_key, str) else None
                sanitized_items.append(
                    [
                        self._redact_encoded(encoded_key, key=None, depth=depth + 1),
                        self._redact_encoded(
                            encoded_value,
                            key=plain_key,
                            depth=depth + 1,
                        ),
                    ]
                )
            output["items"] = sanitized_items
            return output

        output: dict[str, Any] = {}
        for item_key, item_value in list(value.items())[: self.config.max_collection_items]:
            item_key_text = str(item_key)
            output[item_key_text] = self._redact_encoded(
                item_value,
                key=item_key_text if item_key_text not in {_TYPE_MARKER, "value"} else key,
                depth=depth + 1,
            )
        return output

    def _is_sensitive_key(self, key: str) -> bool:
        normalized = key.casefold().replace("-", "_").replace(" ", "_")
        return normalized in self.sensitive_fields

    def _redact_text(self, text: str) -> str:
        output = text
        for pattern in self.patterns:
            output = pattern.sub(REDACTED, output)
        if len(output) > self.config.max_value_length:
            output = output[: self.config.max_value_length] + "…[TRUNCATED]"
        return output

    @staticmethod
    def _safe_repr(value: Any) -> str:
        try:
            return repr(value)
        except Exception as error:  # repr de terceiros pode falhar
            return f"<unrepresentable {type(value).__module__}.{type(value).__qualname__}: {type(error).__name__}>"
