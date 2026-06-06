"""Validação das novas restrições de segurança na TraceSeedConfig."""

from __future__ import annotations

import unittest

from traceseed import TraceSeedConfig
from traceseed.errors import ConfigurationError


class TestArchiveSizeConsistency(unittest.TestCase):
    def test_total_size_less_than_file_size_raises(self):
        with self.assertRaises(ConfigurationError) as ctx:
            TraceSeedConfig(
                max_archive_file_size=100 * 1024 * 1024,
                max_archive_total_size=10 * 1024 * 1024,
            )
        self.assertIn("max_archive_total_size", str(ctx.exception))

    def test_total_size_equal_file_size_is_valid(self):
        cfg = TraceSeedConfig(
            max_archive_file_size=50 * 1024 * 1024,
            max_archive_total_size=50 * 1024 * 1024,
        )
        self.assertEqual(cfg.max_archive_total_size, cfg.max_archive_file_size)

    def test_manifest_size_greater_than_file_size_raises(self):
        with self.assertRaises(ConfigurationError) as ctx:
            TraceSeedConfig(
                max_archive_file_size=512,
                max_archive_total_size=1024,
                max_manifest_size=1024,
            )
        self.assertIn("max_manifest_size", str(ctx.exception))

    def test_manifest_size_equal_file_size_is_valid(self):
        cfg = TraceSeedConfig(
            max_archive_file_size=1024,
            max_archive_total_size=2048,
            max_manifest_size=1024,
        )
        self.assertEqual(cfg.max_manifest_size, cfg.max_archive_file_size)

    def test_file_size_zero_raises(self):
        with self.assertRaises(ConfigurationError):
            TraceSeedConfig(max_archive_file_size=0)

    def test_total_size_zero_raises(self):
        with self.assertRaises(ConfigurationError):
            TraceSeedConfig(max_archive_total_size=0)

    def test_manifest_size_zero_raises(self):
        with self.assertRaises(ConfigurationError):
            TraceSeedConfig(
                max_archive_file_size=1024,
                max_archive_total_size=2048,
                max_manifest_size=0,
            )


class TestExceptionLimits(unittest.TestCase):
    def test_max_exception_depth_zero_raises(self):
        with self.assertRaises(ConfigurationError) as ctx:
            TraceSeedConfig(max_exception_depth=0)
        self.assertIn("max_exception_depth", str(ctx.exception))

    def test_max_exception_depth_negative_raises(self):
        with self.assertRaises(ConfigurationError):
            TraceSeedConfig(max_exception_depth=-1)

    def test_max_exception_depth_one_is_valid(self):
        cfg = TraceSeedConfig(max_exception_depth=1)
        self.assertEqual(cfg.max_exception_depth, 1)

    def test_max_exception_children_negative_raises(self):
        with self.assertRaises(ConfigurationError) as ctx:
            TraceSeedConfig(max_exception_children=-1)
        self.assertIn("max_exception_children", str(ctx.exception))

    def test_max_exception_children_zero_is_valid(self):
        cfg = TraceSeedConfig(max_exception_children=0)
        self.assertEqual(cfg.max_exception_children, 0)


class TestOperationAndTextLimits(unittest.TestCase):
    def test_max_operation_length_less_than_8_raises(self):
        for bad_value in (0, 1, 7):
            with self.assertRaises(ConfigurationError) as ctx:
                TraceSeedConfig(max_operation_length=bad_value)
            self.assertIn("max_operation_length", str(ctx.exception))

    def test_max_operation_length_8_is_valid(self):
        cfg = TraceSeedConfig(max_operation_length=8)
        self.assertEqual(cfg.max_operation_length, 8)

    def test_max_traceback_text_length_less_than_100_raises(self):
        for bad_value in (0, 50, 99):
            with self.assertRaises(ConfigurationError) as ctx:
                TraceSeedConfig(max_traceback_text_length=bad_value)
            self.assertIn("max_traceback_text_length", str(ctx.exception))

    def test_max_traceback_text_length_100_is_valid(self):
        cfg = TraceSeedConfig(max_traceback_text_length=100)
        self.assertEqual(cfg.max_traceback_text_length, 100)


class TestReplayPayloadLimit(unittest.TestCase):
    def test_max_replay_payload_size_less_than_100_raises(self):
        for bad_value in (0, 50, 99):
            with self.assertRaises(ConfigurationError) as ctx:
                TraceSeedConfig(max_replay_payload_size=bad_value)
            self.assertIn("max_replay_payload_size", str(ctx.exception))

    def test_max_replay_payload_size_100_is_valid(self):
        cfg = TraceSeedConfig(max_replay_payload_size=100)
        self.assertEqual(cfg.max_replay_payload_size, 100)


class TestCaptureArgvDefault(unittest.TestCase):
    def test_capture_argv_defaults_to_false(self):
        """capture_argv deve ser False por padrão (segurança)."""
        cfg = TraceSeedConfig()
        self.assertFalse(cfg.capture_argv)

    def test_capture_argv_can_be_enabled(self):
        cfg = TraceSeedConfig(capture_argv=True)
        self.assertTrue(cfg.capture_argv)

    def test_capture_cwd_defaults_to_true(self):
        cfg = TraceSeedConfig()
        self.assertTrue(cfg.capture_cwd)

    def test_capture_cwd_can_be_disabled(self):
        cfg = TraceSeedConfig(capture_cwd=False)
        self.assertFalse(cfg.capture_cwd)


class TestDefaultValues(unittest.TestCase):
    def test_default_config_is_valid(self):
        cfg = TraceSeedConfig()
        self.assertGreater(cfg.max_exception_depth, 0)
        self.assertGreaterEqual(cfg.max_exception_children, 0)
        self.assertGreaterEqual(cfg.max_operation_length, 8)
        self.assertGreaterEqual(cfg.max_traceback_text_length, 100)
        self.assertGreaterEqual(cfg.max_replay_payload_size, 100)
        self.assertGreaterEqual(cfg.max_archive_total_size, cfg.max_archive_file_size)
        self.assertLessEqual(cfg.max_manifest_size, cfg.max_archive_file_size)


if __name__ == "__main__":
    unittest.main()
