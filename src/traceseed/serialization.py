"""Serialização JSON segura, determinística e parcialmente reversível."""

from __future__ import annotations

import base64
import enum
import json
from dataclasses import asdict, fields, is_dataclass
from datetime import date, datetime, time, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any, Protocol
from uuid import UUID

from .config import TraceSeedConfig
from .errors import SerializationError

_TYPE = "__traceseed_type__"


class ValueCodec(Protocol):
    type_name: str

    def can_encode(self, value: Any) -> bool: ...
    def encode(self, value: Any, serializer: "SafeSerializer") -> Any: ...
    def decode(self, value: Any, serializer: "SafeSerializer") -> Any: ...


class SafeSerializer:
    """Converte valores em estruturas JSON sem executar código arbitrário."""

    def __init__(self, config: TraceSeedConfig) -> None:
        self.config = config
        self._codecs: list[ValueCodec] = []
        self._codecs_by_name: dict[str, ValueCodec] = {}

    def register_codec(self, codec: ValueCodec) -> None:
        if not getattr(codec, "type_name", None):
            raise ValueError("codec precisa declarar type_name")
        self._codecs.append(codec)
        self._codecs_by_name[codec.type_name] = codec

    def encode(self, value: Any) -> Any:
        return self._encode(value, depth=0, seen=set())

    def _encode(self, value: Any, *, depth: int, seen: set[int]) -> Any:
        if depth >= self.config.max_depth:
            return {_TYPE: "max_depth"}
        if value is None or isinstance(value, (bool, int, str)):
            if isinstance(value, str) and len(value) > self.config.max_value_length:
                return value[: self.config.max_value_length] + "…[TRUNCATED]"
            return value
        if isinstance(value, float):
            if value != value:
                return {_TYPE: "float", "value": "nan"}
            if value == float("inf"):
                return {_TYPE: "float", "value": "inf"}
            if value == float("-inf"):
                return {_TYPE: "float", "value": "-inf"}
            return value

        for codec in self._codecs:
            try:
                if codec.can_encode(value):
                    return {_TYPE: codec.type_name, "value": codec.encode(value, self)}
            except Exception as error:
                return {
                    _TYPE: "codec_error",
                    "codec": codec.type_name,
                    "error": type(error).__name__,
                }

        if isinstance(value, bytes):
            data = value[: self.config.max_value_length]
            return {
                _TYPE: "bytes",
                "encoding": "base64",
                "value": base64.b64encode(data).decode("ascii"),
                "truncated": len(value) > len(data),
            }
        if isinstance(value, bytearray):
            return self._encode(bytes(value), depth=depth, seen=seen)
        if isinstance(value, memoryview):
            return self._encode(value.tobytes(), depth=depth, seen=seen)
        if isinstance(value, datetime):
            return {_TYPE: "datetime", "value": value.isoformat()}
        if isinstance(value, date):
            return {_TYPE: "date", "value": value.isoformat()}
        if isinstance(value, time):
            return {_TYPE: "time", "value": value.isoformat()}
        if isinstance(value, timedelta):
            return {_TYPE: "timedelta", "seconds": value.total_seconds()}
        if isinstance(value, Decimal):
            return {_TYPE: "decimal", "value": str(value)}
        if isinstance(value, UUID):
            return {_TYPE: "uuid", "value": str(value)}
        if isinstance(value, Path):
            return {_TYPE: "path", "value": str(value)}
        if isinstance(value, enum.Enum):
            return {
                _TYPE: "enum",
                "module": value.__class__.__module__,
                "class": value.__class__.__qualname__,
                "name": value.name,
                "value": self._encode(value.value, depth=depth + 1, seen=seen),
            }

        track = isinstance(value, (dict, list, tuple, set, frozenset)) or is_dataclass(value)
        identity = id(value)
        if track:
            if identity in seen:
                return {_TYPE: "circular_reference"}
            seen.add(identity)
        try:
            if isinstance(value, dict):
                items = sorted(
                    value.items(),
                    key=lambda item: self._safe_sort_key(item[0]),
                )[: self.config.max_collection_items]
                return {
                    _TYPE: "dict",
                    "items": [
                        [
                            self._encode(k, depth=depth + 1, seen=seen),
                            self._encode(v, depth=depth + 1, seen=seen),
                        ]
                        for k, v in items
                    ],
                    "truncated": len(value) > len(items),
                }
            if isinstance(value, (list, tuple, set, frozenset)):
                items = list(value)[: self.config.max_collection_items]
                kind = type(value).__name__
                if isinstance(value, (set, frozenset)):
                    items.sort(key=self._safe_sort_key)
                return {
                    _TYPE: kind,
                    "items": [self._encode(item, depth=depth + 1, seen=seen) for item in items],
                    "truncated": len(value) > len(items),
                }
            if is_dataclass(value) and not isinstance(value, type):
                data = {}
                for item in fields(value)[: self.config.max_collection_items]:
                    data[item.name] = self._encode(
                        getattr(value, item.name), depth=depth + 1, seen=seen
                    )
                return {
                    _TYPE: "dataclass",
                    "module": value.__class__.__module__,
                    "class": value.__class__.__qualname__,
                    "fields": data,
                }
            return {
                _TYPE: "unresolved",
                "module": type(value).__module__,
                "class": type(value).__qualname__,
                "repr": self.safe_repr(value),
            }
        finally:
            if track:
                seen.discard(identity)

    def decode(self, value: Any, *, allow_imports: bool = False) -> Any:
        """Reconstrói apenas tipos seguros; dataclasses/enums exigem allow_imports."""

        if isinstance(value, list):
            return [self.decode(item, allow_imports=allow_imports) for item in value]
        if not isinstance(value, dict) or _TYPE not in value:
            if isinstance(value, dict):
                return {k: self.decode(v, allow_imports=allow_imports) for k, v in value.items()}
            return value
        kind = value[_TYPE]
        if kind in self._codecs_by_name:
            return self._codecs_by_name[kind].decode(value.get("value"), self)
        if kind == "bytes":
            return base64.b64decode(value["value"])
        if kind == "datetime":
            return datetime.fromisoformat(value["value"])
        if kind == "date":
            return date.fromisoformat(value["value"])
        if kind == "time":
            return time.fromisoformat(value["value"])
        if kind == "timedelta":
            return timedelta(seconds=value["seconds"])
        if kind == "decimal":
            return Decimal(value["value"])
        if kind == "uuid":
            return UUID(value["value"])
        if kind == "path":
            return Path(value["value"])
        if kind == "float":
            return {"nan": float("nan"), "inf": float("inf"), "-inf": float("-inf")}[value["value"]]
        if kind == "dict":
            return {
                self.decode(k, allow_imports=allow_imports): self.decode(v, allow_imports=allow_imports)
                for k, v in value.get("items", [])
            }
        if kind in {"list", "tuple", "set", "frozenset"}:
            items = [self.decode(item, allow_imports=allow_imports) for item in value.get("items", [])]
            return {"list": list, "tuple": tuple, "set": set, "frozenset": frozenset}[kind](items)
        if kind in {"circular_reference", "max_depth", "unresolved", "codec_error"}:
            raise SerializationError(f"valor do tipo {kind!r} não pode ser reconstruído")
        if kind in {"dataclass", "enum"}:
            if not allow_imports:
                raise SerializationError(f"reconstrução de {kind} exige allow_imports=True")
            target = self._import_symbol(value["module"], value["class"])
            if kind == "enum":
                return target[value["name"]]
            decoded_fields = {
                key: self.decode(item, allow_imports=True)
                for key, item in value["fields"].items()
            }
            return target(**decoded_fields)
        raise SerializationError(f"tipo serializado desconhecido: {kind}")

    def dumps(self, value: Any, *, pretty: bool | None = None) -> str:
        encoded = self.encode(value)
        if pretty is None:
            pretty = self.config.write_pretty_json
        return json.dumps(
            encoded,
            ensure_ascii=False,
            sort_keys=True,
            indent=2 if pretty else None,
            separators=None if pretty else (",", ":"),
        )

    def loads(self, payload: str, *, allow_imports: bool = False) -> Any:
        try:
            value = json.loads(payload)
        except json.JSONDecodeError as error:
            raise SerializationError(str(error)) from error
        return self.decode(value, allow_imports=allow_imports)

    @staticmethod
    def safe_repr(value: Any) -> str:
        try:
            result = repr(value)
        except Exception as error:
            return f"<unrepresentable: {type(error).__name__}>"
        return result

    @staticmethod
    def _safe_sort_key(value: Any) -> str:
        try:
            return f"{type(value).__module__}.{type(value).__qualname__}:{repr(value)}"
        except Exception:
            return f"{type(value).__module__}.{type(value).__qualname__}:{id(value)}"

    @staticmethod
    def _import_symbol(module_name: str, qualname: str) -> Any:
        import importlib

        module = importlib.import_module(module_name)
        target: Any = module
        for part in qualname.split("."):
            if part == "<locals>" or part.startswith("__"):
                raise SerializationError("qualname inseguro ou não importável")
            target = getattr(target, part)
        return target
