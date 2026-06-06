import unittest
from dataclasses import dataclass

from traceseed.config import TraceSeedConfig
from traceseed.redaction import (
    CIRCULAR_REFERENCE,
    MAX_DEPTH,
    REDACTED,
    TRUNCATED,
    Redactor,
)


@dataclass
class Credentials:
    username: str
    password: str


class BrokenRepr:
    def __repr__(self):
        raise RuntimeError("boom")


class RedactionTests(unittest.TestCase):
    def setUp(self):
        self.redactor = Redactor(TraceSeedConfig())

    def test_redacts_sensitive_key(self):
        self.assertEqual(self.redactor.redact({"password": "abc"})["password"], REDACTED)

    def test_redacts_case_insensitively(self):
        self.assertEqual(self.redactor.redact({"TOKEN": "abc"})["TOKEN"], REDACTED)

    def test_redacts_hyphenated_key(self):
        self.assertEqual(self.redactor.redact({"api-key": "abc"})["api-key"], REDACTED)

    def test_redacts_nested_values(self):
        result = self.redactor.redact({"user": {"secret": "x"}})
        self.assertEqual(result["user"]["secret"], REDACTED)

    def test_redacts_bearer_token_in_text(self):
        result = self.redactor.redact("Authorization: Bearer abc.DEF-123")
        self.assertNotIn("abc.DEF-123", result)
        self.assertIn(REDACTED, result)

    def test_redacts_card_like_number(self):
        result = self.redactor.redact("card 4111 1111 1111 1111")
        self.assertNotIn("4111", result)

    def test_truncates_long_string(self):
        config = TraceSeedConfig(max_value_length=32)
        result = Redactor(config).redact("x" * 100)
        self.assertTrue(result.endswith("[TRUNCATED]"))

    def test_limits_collection_size(self):
        config = TraceSeedConfig(max_collection_items=2)
        result = Redactor(config).redact([1, 2, 3])
        self.assertEqual(result[-1], TRUNCATED)

    def test_limits_dict_size(self):
        config = TraceSeedConfig(max_collection_items=1)
        result = Redactor(config).redact({"a": 1, "b": 2})
        self.assertIn(TRUNCATED, result)

    def test_detects_circular_list(self):
        value = []
        value.append(value)
        result = self.redactor.redact(value)
        self.assertEqual(result[0], CIRCULAR_REFERENCE)

    def test_max_depth(self):
        config = TraceSeedConfig(max_depth=2)
        result = Redactor(config).redact({"a": {"b": {"c": 1}}})
        self.assertEqual(result["a"]["b"], MAX_DEPTH)

    def test_dataclass_is_sanitized(self):
        result = self.redactor.redact(Credentials("igor", "secret"))
        self.assertEqual(result["username"], "igor")
        self.assertEqual(result["password"], REDACTED)

    def test_bytes_are_decoded_and_redacted(self):
        result = self.redactor.redact(b"Bearer abc123456")
        self.assertIn(REDACTED, result)

    def test_broken_repr_does_not_crash(self):
        result = self.redactor.redact(BrokenRepr())
        self.assertIn("unrepresentable", result)

    def test_set_becomes_list(self):
        result = self.redactor.redact({1, 2})
        self.assertCountEqual(result, [1, 2])

    def test_custom_redactor(self):
        marker = object()
        redactor = Redactor(
            TraceSeedConfig(), custom=lambda key, value: REDACTED if value is marker else value
        )
        self.assertEqual(redactor.redact(marker), REDACTED)


class EncodedRedactionTests(unittest.TestCase):
    def test_redacts_sensitive_key_in_serialized_dict_pairs(self):
        redactor = Redactor(TraceSeedConfig())
        encoded = {
            "__traceseed_type__": "dict",
            "items": [["password", "secret"], ["visible", 1]],
            "truncated": False,
        }
        result = redactor.redact_encoded(encoded)
        self.assertEqual(result["items"][0][1], REDACTED)
        self.assertEqual(result["items"][1][1], 1)

    def test_preserves_type_marker(self):
        redactor = Redactor(TraceSeedConfig())
        encoded = {"__traceseed_type__": "uuid", "value": "123"}
        result = redactor.redact_encoded(encoded)
        self.assertEqual(result["__traceseed_type__"], "uuid")

    def test_redacts_dataclass_field_in_encoded_tree(self):
        redactor = Redactor(TraceSeedConfig())
        encoded = {
            "__traceseed_type__": "dataclass",
            "module": "x",
            "class": "Credentials",
            "fields": {"username": "igor", "password": "secret"},
        }
        result = redactor.redact_encoded(encoded)
        self.assertEqual(result["fields"]["password"], REDACTED)
