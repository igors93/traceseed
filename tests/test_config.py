import unittest
from pathlib import Path

from traceseed.config import TraceSeedConfig, configure, get_config, reset_config
from traceseed.errors import ConfigurationError


class ConfigTests(unittest.TestCase):
    def tearDown(self):
        reset_config()

    def test_default_output_is_path(self):
        self.assertIsInstance(TraceSeedConfig().output_directory, Path)

    def test_string_output_is_converted(self):
        self.assertEqual(TraceSeedConfig(output_directory="tmp").output_directory, Path("tmp"))

    def test_fields_are_casefolded(self):
        config = TraceSeedConfig(redact_fields=frozenset({"TOKEN", "Password"}))
        self.assertEqual(config.redact_fields, frozenset({"token", "password"}))

    def test_patterns_become_tuple(self):
        config = TraceSeedConfig(redact_patterns=["a", "b"])
        self.assertEqual(config.redact_patterns, ("a", "b"))

    def test_invalid_max_value_length(self):
        with self.assertRaises(ConfigurationError):
            TraceSeedConfig(max_value_length=10)

    def test_invalid_collection_items(self):
        with self.assertRaises(ConfigurationError):
            TraceSeedConfig(max_collection_items=0)

    def test_invalid_depth(self):
        with self.assertRaises(ConfigurationError):
            TraceSeedConfig(max_depth=0)

    def test_invalid_breadcrumb_limit(self):
        with self.assertRaises(ConfigurationError):
            TraceSeedConfig(max_breadcrumbs=0)

    def test_invalid_frame_limit(self):
        with self.assertRaises(ConfigurationError):
            TraceSeedConfig(max_frames=0)

    def test_invalid_fingerprint_frame_limit(self):
        with self.assertRaises(ConfigurationError):
            TraceSeedConfig(fingerprint_frame_limit=0)

    def test_invalid_prefix(self):
        with self.assertRaises(ConfigurationError):
            TraceSeedConfig(filename_prefix="   ")

    def test_with_overrides_is_immutable(self):
        original = TraceSeedConfig()
        updated = original.with_overrides(max_depth=3)
        self.assertEqual(original.max_depth, 8)
        self.assertEqual(updated.max_depth, 3)

    def test_with_redact_fields_adds(self):
        config = TraceSeedConfig().with_redact_fields(["cpf"])
        self.assertIn("cpf", config.redact_fields)
        self.assertIn("password", config.redact_fields)

    def test_configure_and_get(self):
        expected = TraceSeedConfig(max_depth=3)
        configure(expected)
        self.assertIs(get_config(), expected)

    def test_configure_with_overrides(self):
        configure(TraceSeedConfig(), max_depth=4)
        self.assertEqual(get_config().max_depth, 4)

    def test_configure_rejects_wrong_type(self):
        with self.assertRaises(TypeError):
            configure("wrong")

    def test_reset_config(self):
        configure(max_depth=2)
        reset = reset_config()
        self.assertEqual(reset.max_depth, 8)
