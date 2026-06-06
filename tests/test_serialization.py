import enum
import math
import unittest
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from uuid import UUID, uuid4

from traceseed.config import TraceSeedConfig
from traceseed.errors import SerializationError
from traceseed.serialization import SafeSerializer


class Color(enum.Enum):
    RED = "red"


@dataclass
class Point:
    x: int
    y: int


class BrokenRepr:
    def __repr__(self):
        raise RuntimeError("broken")


class SerializationTests(unittest.TestCase):
    def setUp(self):
        self.serializer = SafeSerializer(TraceSeedConfig())

    def roundtrip(self, value, *, allow_imports=False):
        return self.serializer.decode(self.serializer.encode(value), allow_imports=allow_imports)

    def test_primitives_roundtrip(self):
        for value in [None, True, 1, 1.5, "text"]:
            with self.subTest(value=value):
                self.assertEqual(self.roundtrip(value), value)

    def test_bytes_roundtrip(self):
        self.assertEqual(self.roundtrip(b"abc"), b"abc")

    def test_datetime_roundtrip(self):
        value = datetime(2026, 1, 2, 3, 4, tzinfo=timezone.utc)
        self.assertEqual(self.roundtrip(value), value)

    def test_date_roundtrip(self):
        value = date(2026, 1, 2)
        self.assertEqual(self.roundtrip(value), value)

    def test_time_roundtrip(self):
        value = time(12, 30, 1)
        self.assertEqual(self.roundtrip(value), value)

    def test_timedelta_roundtrip(self):
        value = timedelta(days=2, seconds=3)
        self.assertEqual(self.roundtrip(value), value)

    def test_decimal_roundtrip(self):
        value = Decimal("10.25")
        self.assertEqual(self.roundtrip(value), value)

    def test_uuid_roundtrip(self):
        value = uuid4()
        self.assertEqual(self.roundtrip(value), value)

    def test_path_roundtrip(self):
        value = Path("a/b")
        self.assertEqual(self.roundtrip(value), value)

    def test_list_tuple_set_frozenset_roundtrip(self):
        values = [[1, 2], (1, 2), {1, 2}, frozenset({1, 2})]
        for value in values:
            with self.subTest(type=type(value)):
                decoded = self.roundtrip(value)
                self.assertEqual(decoded, value)
                self.assertIs(type(decoded), type(value))

    def test_dict_with_non_string_keys(self):
        value = {1: "a", (2, 3): "b"}
        self.assertEqual(self.roundtrip(value), value)

    def test_nan_roundtrip(self):
        self.assertTrue(math.isnan(self.roundtrip(float("nan"))))

    def test_infinity_roundtrip(self):
        self.assertEqual(self.roundtrip(float("inf")), float("inf"))
        self.assertEqual(self.roundtrip(float("-inf")), float("-inf"))

    def test_dataclass_requires_import_permission(self):
        encoded = self.serializer.encode(Point(1, 2))
        with self.assertRaises(SerializationError):
            self.serializer.decode(encoded)
        self.assertEqual(self.serializer.decode(encoded, allow_imports=True), Point(1, 2))

    def test_enum_requires_import_permission(self):
        encoded = self.serializer.encode(Color.RED)
        with self.assertRaises(SerializationError):
            self.serializer.decode(encoded)
        self.assertIs(self.serializer.decode(encoded, allow_imports=True), Color.RED)

    def test_unknown_object_becomes_unresolved(self):
        encoded = self.serializer.encode(object())
        self.assertEqual(encoded["__traceseed_type__"], "unresolved")
        with self.assertRaises(SerializationError):
            self.serializer.decode(encoded)

    def test_broken_repr_is_safe(self):
        encoded = self.serializer.encode(BrokenRepr())
        self.assertIn("unrepresentable", encoded["repr"])

    def test_circular_reference_is_detected(self):
        value = []
        value.append(value)
        encoded = self.serializer.encode(value)
        self.assertEqual(encoded["items"][0]["__traceseed_type__"], "circular_reference")

    def test_max_depth_is_detected(self):
        serializer = SafeSerializer(TraceSeedConfig(max_depth=2))
        encoded = serializer.encode([[[1]]])
        self.assertEqual(encoded["items"][0]["items"][0]["__traceseed_type__"], "max_depth")

    def test_collection_truncation(self):
        serializer = SafeSerializer(TraceSeedConfig(max_collection_items=2))
        encoded = serializer.encode([1, 2, 3])
        self.assertTrue(encoded["truncated"])
        self.assertEqual(len(encoded["items"]), 2)

    def test_string_truncation(self):
        serializer = SafeSerializer(TraceSeedConfig(max_value_length=32))
        encoded = serializer.encode("x" * 100)
        self.assertTrue(encoded.endswith("[TRUNCATED]"))

    def test_dumps_is_deterministic(self):
        first = self.serializer.dumps({"b": 2, "a": 1}, pretty=False)
        second = self.serializer.dumps({"a": 1, "b": 2}, pretty=False)
        self.assertEqual(first, second)

    def test_loads_invalid_json(self):
        with self.assertRaises(SerializationError):
            self.serializer.loads("{")

    def test_unknown_serialized_type(self):
        with self.assertRaises(SerializationError):
            self.serializer.decode({"__traceseed_type__": "mystery"})

    def test_import_rejects_dunder(self):
        with self.assertRaises(SerializationError):
            self.serializer._import_symbol("tests.test_serialization", "__dict__")

    def test_custom_codec(self):
        class ComplexCodec:
            type_name = "complex"
            def can_encode(self, value): return isinstance(value, complex)
            def encode(self, value, serializer): return [value.real, value.imag]
            def decode(self, value, serializer): return complex(*value)

        self.serializer.register_codec(ComplexCodec())
        self.assertEqual(self.roundtrip(2 + 3j), 2 + 3j)

    def test_codec_requires_type_name(self):
        class InvalidCodec:
            pass
        with self.assertRaises(ValueError):
            self.serializer.register_codec(InvalidCodec())
