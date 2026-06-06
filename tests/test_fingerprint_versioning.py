"""Verifica determinismo, versionamento e campo cause_type da fingerprint."""

import unittest

from traceseed import TraceSeedConfig
from traceseed.fingerprint import _ALGORITHM, _ALGORITHM_VERSION, Fingerprinter
from traceseed.models import ExceptionInfo, FrameInfo


def _exc_info(msg="error", type_name="ValueError", module="builtins", cause=None):
    return ExceptionInfo(
        module=module,
        type_name=type_name,
        message=msg,
        representation=f"{type_name}({msg!r})",
        cause=cause,
        context=None,
        suppress_context=False,
        notes=(),
        children=(),
    )


def _frame(filename="app/main.py", function="process"):
    return FrameInfo(
        filename=filename,
        function=function,
        line_number=42,
        module="app.main",
        locals={},
        source_line=None,
    )


class TestFingerprintVersioning(unittest.TestCase):
    def setUp(self):
        self.cfg = TraceSeedConfig()
        self.fp = Fingerprinter(self.cfg)

    def test_canonical_contains_algorithm_field(self):
        details = self.fp.generate(_exc_info(), (_frame(),))
        self.assertEqual(details.canonical["algorithm"], _ALGORITHM)

    def test_canonical_contains_algorithm_version(self):
        details = self.fp.generate(_exc_info(), (_frame(),))
        self.assertEqual(details.canonical["algorithm_version"], _ALGORITHM_VERSION)
        self.assertIsInstance(details.canonical["algorithm_version"], int)

    def test_fingerprint_is_deterministic(self):
        exc = _exc_info("connection refused")
        frames = (_frame("server/handler.py", "handle"),)
        d1 = self.fp.generate(exc, frames)
        d2 = self.fp.generate(exc, frames)
        self.assertEqual(d1.value, d2.value)

    def test_different_exceptions_different_fingerprints(self):
        d1 = self.fp.generate(_exc_info("error A"), (_frame(),))
        d2 = self.fp.generate(_exc_info("error B"), (_frame(),))
        self.assertNotEqual(d1.value, d2.value)

    def test_cause_type_is_included_when_present(self):
        cause = _exc_info("original", "OSError", "builtins")
        exc = _exc_info("wrapped", "RuntimeError", "builtins", cause=cause)
        details = self.fp.generate(exc, (_frame(),))
        self.assertIsNotNone(details.canonical["cause_type"])
        self.assertIn("OSError", details.canonical["cause_type"])

    def test_cause_type_is_none_without_cause(self):
        details = self.fp.generate(_exc_info("no cause"), (_frame(),))
        self.assertIsNone(details.canonical["cause_type"])

    def test_cause_changes_fingerprint(self):
        exc_no_cause = _exc_info("err")
        cause = _exc_info("root", "OSError", "builtins")
        exc_with_cause = _exc_info("err", cause=cause)
        d1 = self.fp.generate(exc_no_cause, (_frame(),))
        d2 = self.fp.generate(exc_with_cause, (_frame(),))
        self.assertNotEqual(d1.value, d2.value)

    def test_uuid_in_message_normalized(self):
        exc_uuid = _exc_info("not found: 123e4567-e89b-12d3-a456-426614174000")
        exc_num = _exc_info("not found: deadbeef-dead-dead-dead-deaddeadbeef")
        # Ambos devem ter mesma fingerprint (normalização de UUID)
        d_uuid = self.fp.generate(exc_uuid, (_frame(),))
        self.fp.generate(exc_num, (_frame(),))
        # Ambos contêm <uuid> no canonical normalizado
        self.assertIn("<uuid>", d_uuid.canonical["message"])

    def test_numbers_in_message_normalized(self):
        exc1 = _exc_info("timeout after 30 seconds")
        exc2 = _exc_info("timeout after 60 seconds")
        d1 = self.fp.generate(exc1, (_frame(),))
        d2 = self.fp.generate(exc2, (_frame(),))
        self.assertEqual(d1.value, d2.value)

    def test_frames_use_module_key(self):
        """Frames usam 'module' (estável entre máquinas) em vez de 'filename'."""
        frame = _frame("app/main.py")
        exc = _exc_info()
        details = self.fp.generate(exc, (frame,))
        for frame_data in details.canonical["frames"]:
            self.assertIn("module", frame_data)
            self.assertNotIn("filename", frame_data)

    def test_same_module_different_absolute_paths_same_fingerprint(self):
        """Caminhos absolutos distintos com mesmo módulo geram a mesma fingerprint."""
        frame_user1 = FrameInfo(
            filename="/home/user1/project/src/app.py",
            function="process",
            line_number=42,
            module="app.main",
            locals={},
            source_line=None,
        )
        frame_user2 = FrameInfo(
            filename="/home/user2/project/src/app.py",
            function="process",
            line_number=42,
            module="app.main",
            locals={},
            source_line=None,
        )
        exc = _exc_info()
        d1 = self.fp.generate(exc, (frame_user1,))
        d2 = self.fp.generate(exc, (frame_user2,))
        self.assertEqual(d1.value, d2.value)

    def test_different_modules_different_fingerprints(self):
        """Módulos distintos ainda produzem fingerprints distintas."""
        frame_a = FrameInfo(
            filename="/home/user/project/app_a.py",
            function="handle",
            line_number=10,
            module="app.service_a",
            locals={},
            source_line=None,
        )
        frame_b = FrameInfo(
            filename="/home/user/project/app_b.py",
            function="handle",
            line_number=10,
            module="app.service_b",
            locals={},
            source_line=None,
        )
        exc = _exc_info()
        d1 = self.fp.generate(exc, (frame_a,))
        d2 = self.fp.generate(exc, (frame_b,))
        self.assertNotEqual(d1.value, d2.value)

    def test_fingerprint_value_length(self):
        details = self.fp.generate(_exc_info(), (_frame(),))
        # 32 chars = 128 bits em hex
        self.assertEqual(len(details.value), 32)


if __name__ == "__main__":
    unittest.main()
