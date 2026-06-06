import unittest

from traceseed.config import TraceSeedConfig
from traceseed.fingerprint import Fingerprinter
from traceseed.models import ExceptionInfo, FrameInfo


class FingerprintTests(unittest.TestCase):
    def setUp(self):
        self.fp = Fingerprinter(TraceSeedConfig())
        self.frame = FrameInfo("/home/app/service.py", "run", 10, module="app.service")

    def info(self, message):
        return ExceptionInfo("builtins", "ValueError", message, f"ValueError({message!r})")

    def test_same_input_same_fingerprint(self):
        a = self.fp.generate(self.info("bad 123"), (self.frame,))
        b = self.fp.generate(self.info("bad 123"), (self.frame,))
        self.assertEqual(a.value, b.value)

    def test_numbers_are_normalized(self):
        a = self.fp.generate(self.info("customer 123 not found"), (self.frame,))
        b = self.fp.generate(self.info("customer 999 not found"), (self.frame,))
        self.assertEqual(a.value, b.value)

    def test_uuid_is_normalized(self):
        a = self.fp.normalize_message("id 123e4567-e89b-12d3-a456-426614174000")
        self.assertEqual(a, "id <uuid>")

    def test_hex_is_normalized(self):
        self.assertEqual(self.fp.normalize_message("at 0xABCDEF"), "at <hex>")

    def test_long_token_is_normalized(self):
        self.assertEqual(
            self.fp.normalize_message("token abcdefghijklmnopqrstuvwxyz123"), "token <token>"
        )

    def test_different_exception_type_changes_fingerprint(self):
        one = self.fp.generate(self.info("bad"), (self.frame,))
        other_info = ExceptionInfo("builtins", "TypeError", "bad", "TypeError('bad')")
        two = self.fp.generate(other_info, (self.frame,))
        self.assertNotEqual(one.value, two.value)

    def test_different_frame_changes_fingerprint(self):
        one = self.fp.generate(self.info("bad"), (self.frame,))
        other = FrameInfo("/home/app/other.py", "run", 10, module="app.other")
        two = self.fp.generate(self.info("bad"), (other,))
        self.assertNotEqual(one.value, two.value)

    def test_path_is_shortened(self):
        details = self.fp.generate(self.info("bad"), (self.frame,))
        filename = details.canonical["frames"][0]["filename"]
        self.assertFalse(filename.startswith("/"))

    def test_normalization_can_be_disabled(self):
        fp = Fingerprinter(TraceSeedConfig(normalize_exception_messages=False))
        a = fp.generate(self.info("bad 1"), (self.frame,))
        b = fp.generate(self.info("bad 2"), (self.frame,))
        self.assertNotEqual(a.value, b.value)

    def test_frame_limit_uses_last_frames(self):
        fp = Fingerprinter(TraceSeedConfig(fingerprint_frame_limit=1))
        frames = (
            FrameInfo("a.py", "a", 1),
            FrameInfo("b.py", "b", 2),
        )
        details = fp.generate(self.info("bad"), frames)
        self.assertEqual(len(details.canonical["frames"]), 1)
        self.assertEqual(details.canonical["frames"][0]["function"], "b")
