"""Deterministic JSON-safe serialization with bounded decoding."""

from __future__ import annotations

import base64
import binascii
import enum
import importlib
import json
from dataclasses import fields, is_dataclass
from datetime import date, datetime, time, timedelta
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Protocol
from uuid import UUID

from .config import TraceSeedConfig
from .errors import SerializationError

_TYPE = "__traceseed_type__"


class ValueCodec(Protocol):
    type_name: str

    def can_encode(self, value: Any) -> bool: ...

    def encode(self, value: Any, serializer: SafeSerializer) -> Any: ...

    def decode(self, value: Any, serializer: SafeSerializer) -> Any: ...


class SafeSerializer:
    """Convert supported values to and from a typed JSON tree without pickle."""

    def __init__(self, config: TraceSeedConfig) -> None:
        self.config = config
        self._codecs: list[ValueCodec] = []
        self._codecs_by_name: dict[str, ValueCodec] = {}

    def register_codec(self, codec: ValueCodec) -> None:
        type_name = getattr(codec, "type_name", None)
        if not isinstance(type_name, str) or not type_name.strip():
            raise ValueError("codec must declare a non-empty type_name")
        if type_name in self._codecs_by_name:
            raise ValueError(f"codec type_name {type_name!r} is already registered")
        self._codecs.append(codec)
        self._codecs_by_name[type_name] = codec

    def encode(self, value: Any) -> Any:
        return self._encode(value, depth=0, seen=set())

    def _encode(self, value: Any, *, depth: int, seen: set[int]) -> Any:
        if depth >= self.config.max_depth:
            return {_TYPE: "max_depth"}
        if value is None or isinstance(value, (bool, int)):
            return value
        if isinstance(value, str):
            if len(value) > self.config.max_value_length:
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

        for codec in tuple(self._codecs):
            try:
                if codec.can_encode(value):
                    encoded = codec.encode(value, self)
                    return {_TYPE: codec.type_name, "value": encoded}
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

        track = isinstance(value, (dict, list, tuple, set, frozenset)) or (
            is_dataclass(value) and not isinstance(value, type)
        )
        identity = id(value)
        if track:
            if identity in seen:
                return {_TYPE: "circular_reference"}
            seen.add(identity)
        try:
            if isinstance(value, dict):
                try:
                    sorted_items = sorted(
                        value.items(), key=lambda pair: self._safe_sort_key(pair[0])
                    )
                except Exception:
                    sorted_items = list(value.items())
                items = sorted_items[: self.config.max_collection_items]
                return {
                    _TYPE: "dict",
                    "items": [
                        [
                            self._encode(key, depth=depth + 1, seen=seen),
                            self._encode(item, depth=depth + 1, seen=seen),
                        ]
                        for key, item in items
                    ],
                    "truncated": len(value) > len(items),
                }
            if isinstance(value, (list, tuple, set, frozenset)):
                try:
                    items = list(value)
                except Exception:
                    return {
                        _TYPE: "unresolved",
                        "module": type(value).__module__,
                        "class": type(value).__qualname__,
                        "repr": self.safe_repr(value),
                    }
                if isinstance(value, (set, frozenset)):
                    items.sort(key=self._safe_sort_key)
                limited = items[: self.config.max_collection_items]
                return {
                    _TYPE: type(value).__name__,
                    "items": [self._encode(item, depth=depth + 1, seen=seen) for item in limited],
                    "truncated": len(items) > len(limited),
                }
            if is_dataclass(value) and not isinstance(value, type):
                all_fields = fields(value)
                selected = all_fields[: self.config.max_collection_items]
                encoded_fields: dict[str, Any] = {}
                for item in selected:
                    try:
                        field_value = getattr(value, item.name)
                    except Exception as error:
                        encoded_fields[item.name] = {
                            _TYPE: "codec_error",
                            "codec": "dataclass-field",
                            "error": type(error).__name__,
                        }
                    else:
                        encoded_fields[item.name] = self._encode(
                            field_value,
                            depth=depth + 1,
                            seen=seen,
                        )
                return {
                    _TYPE: "dataclass",
                    "module": value.__class__.__module__,
                    "class": value.__class__.__qualname__,
                    "fields": encoded_fields,
                    "truncated": len(all_fields) > len(selected),
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
        try:
            return self._decode(value, allow_imports=allow_imports, depth=0)
        except SerializationError:
            raise
        except (ValueError, TypeError, KeyError, AttributeError, binascii.Error) as error:
            raise SerializationError(str(error)) from error
        except RecursionError as error:
            raise SerializationError("serialized value exceeds the decode depth limit") from error

    def _decode(self, value: Any, *, allow_imports: bool, depth: int) -> Any:
        if depth >= self.config.max_depth * 4:
            raise SerializationError("serialized value exceeds the decode depth limit")
        if isinstance(value, list):
            return [
                self._decode(item, allow_imports=allow_imports, depth=depth + 1) for item in value
            ]
        if not isinstance(value, dict) or _TYPE not in value:
            if isinstance(value, dict):
                return {
                    key: self._decode(item, allow_imports=allow_imports, depth=depth + 1)
                    for key, item in value.items()
                }
            return value

        kind = value.get(_TYPE)
        if not isinstance(kind, str):
            raise SerializationError("serialized type marker must be a string")
        if kind in self._codecs_by_name:
            try:
                return self._codecs_by_name[kind].decode(value.get("value"), self)
            except SerializationError:
                raise
            except Exception as error:
                raise SerializationError(
                    f"codec {kind!r} failed to decode: {type(error).__name__}: {error}"
                ) from error
        if kind == "bytes":
            if value.get("encoding") != "base64" or not isinstance(value.get("value"), str):
                raise SerializationError("invalid bytes encoding")
            try:
                return base64.b64decode(value["value"], validate=True)
            except (ValueError, binascii.Error) as error:
                raise SerializationError("invalid base64 bytes payload") from error
        if kind == "datetime":
            return datetime.fromisoformat(self._required_string(value, "value"))
        if kind == "date":
            return date.fromisoformat(self._required_string(value, "value"))
        if kind == "time":
            return time.fromisoformat(self._required_string(value, "value"))
        if kind == "timedelta":
            seconds = value.get("seconds")
            if not isinstance(seconds, (int, float)) or isinstance(seconds, bool):
                raise SerializationError("invalid timedelta seconds")
            return timedelta(seconds=seconds)
        if kind == "decimal":
            try:
                return Decimal(self._required_string(value, "value"))
            except InvalidOperation as error:
                raise SerializationError("invalid decimal value") from error
        if kind == "uuid":
            try:
                return UUID(self._required_string(value, "value"))
            except ValueError as error:
                raise SerializationError("invalid UUID value") from error
        if kind == "path":
            return Path(self._required_string(value, "value"))
        if kind == "float":
            float_kind = self._required_string(value, "value")
            values = {"nan": float("nan"), "inf": float("inf"), "-inf": float("-inf")}
            if float_kind not in values:
                raise SerializationError("invalid special float value")
            return values[float_kind]
        if kind == "dict":
            pairs = value.get("items")
            if not isinstance(pairs, list):
                raise SerializationError("serialized dict items must be a list")
            result: dict[Any, Any] = {}
            for pair in pairs:
                if not isinstance(pair, list) or len(pair) != 2:
                    raise SerializationError("serialized dict item must be a key/value pair")
                key = self._decode(pair[0], allow_imports=allow_imports, depth=depth + 1)
                item = self._decode(pair[1], allow_imports=allow_imports, depth=depth + 1)
                try:
                    result[key] = item
                except TypeError as error:
                    raise SerializationError("decoded dictionary key is not hashable") from error
            return result
        if kind in {"list", "tuple", "set", "frozenset"}:
            raw_items = value.get("items")
            if not isinstance(raw_items, list):
                raise SerializationError(f"serialized {kind} items must be a list")
            items = [
                self._decode(item, allow_imports=allow_imports, depth=depth + 1)
                for item in raw_items
            ]
            constructors = {"list": list, "tuple": tuple, "set": set, "frozenset": frozenset}
            try:
                return constructors[kind](items)
            except TypeError as error:
                raise SerializationError(f"invalid serialized {kind}") from error
        if kind in {"circular_reference", "max_depth", "unresolved", "codec_error"}:
            raise SerializationError(f"value of type {kind!r} cannot be reconstructed")
        if kind in {"dataclass", "enum"}:
            if not allow_imports:
                raise SerializationError(f"reconstructing {kind} requires allow_imports=True")
            target = self._import_symbol(
                self._required_string(value, "module"),
                self._required_string(value, "class"),
            )
            if kind == "enum":
                name = self._required_string(value, "name")
                try:
                    return target[name]
                except Exception as error:
                    raise SerializationError("invalid enum member") from error
            raw_fields = value.get("fields")
            if not isinstance(raw_fields, dict):
                raise SerializationError("serialized dataclass fields must be an object")
            decoded_fields = {
                key: self._decode(item, allow_imports=True, depth=depth + 1)
                for key, item in raw_fields.items()
            }
            try:
                return target(**decoded_fields)
            except Exception as error:
                raise SerializationError("unable to reconstruct dataclass") from error
        raise SerializationError(f"unknown serialized type: {kind}")

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
            return repr(value)
        except Exception as error:
            return f"<unrepresentable: {type(error).__name__}>"

    @staticmethod
    def _safe_sort_key(value: Any) -> str:
        try:
            return f"{type(value).__module__}.{type(value).__qualname__}:{repr(value)}"
        except Exception:
            return f"{type(value).__module__}.{type(value).__qualname__}"

    @staticmethod
    def _required_string(value: dict[str, Any], key: str) -> str:
        result = value.get(key)
        if not isinstance(result, str):
            raise SerializationError(f"serialized field {key!r} must be a string")
        return result

    @staticmethod
    def _import_symbol(module_name: str, qualname: str) -> Any:
        if not module_name or module_name == "__main__":
            raise SerializationError("module is not importable")
        try:
            module = importlib.import_module(module_name)
            target: Any = module
            for part in qualname.split("."):
                if not part or part == "<locals>" or part.startswith("__"):
                    raise SerializationError("unsafe or non-importable qualname")
                target = getattr(target, part)
            return target
        except SerializationError:
            raise
        except (ImportError, AttributeError) as error:
            raise SerializationError("unable to import serialized symbol") from error
