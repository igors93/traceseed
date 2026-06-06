"""Portabilidade de fingerprints: module-based, estável entre máquinas."""

from __future__ import annotations

import unittest

from traceseed import TraceSeedConfig
from traceseed.fingerprint import _ALGORITHM_VERSION, Fingerprinter
from traceseed.models import ExceptionInfo, FrameInfo


def _fp() -> Fingerprinter:
    return Fingerprinter(TraceSeedConfig())


def _make_exc_info(module: str = "myapp.services", type_name: str = "ValueError") -> ExceptionInfo:
    return ExceptionInfo(
        module=module,
        type_name=type_name,
        message="test error",
        representation="ValueError('test error')",
    )


def _make_frame(
    module: str, function: str, filename: str = "/home/user/app/services.py"
) -> FrameInfo:
    return FrameInfo(
        filename=filename,
        line_number=42,
        function=function,
        module=module,
        source_line="raise ValueError('test error')",
        locals={},
    )


class TestFingerprintAlgorithmVersion(unittest.TestCase):
    def test_algorithm_version_is_2(self):
        """Versão 2 usa module em vez de filename para estabilidade cross-machine."""
        self.assertEqual(_ALGORITHM_VERSION, 2)

    def test_canonical_includes_algorithm_version(self):
        fp = _fp()
        exc = _make_exc_info()
        frames = (_make_frame("myapp.services", "process"),)
        details = fp.generate(exc, frames)
        self.assertEqual(details.canonical["algorithm_version"], 2)


class TestFingerprintModuleUsage(unittest.TestCase):
    def test_frame_uses_module_not_filename(self):
        """Frames canônicos devem usar 'module', não 'filename'."""
        fp = _fp()
        exc = _make_exc_info()
        frames = (_make_frame("myapp.services", "process"),)
        details = fp.generate(exc, frames)
        frame_data = details.canonical["frames"][0]
        self.assertIn("module", frame_data)
        self.assertNotIn("filename", frame_data)

    def test_module_value_matches_frame_module(self):
        fp = _fp()
        exc = _make_exc_info()
        frames = (_make_frame("myapp.services", "process"),)
        details = fp.generate(exc, frames)
        self.assertEqual(details.canonical["frames"][0]["module"], "myapp.services")

    def test_function_included_in_canonical_frame(self):
        fp = _fp()
        exc = _make_exc_info()
        frames = (_make_frame("myapp.services", "process_order"),)
        details = fp.generate(exc, frames)
        self.assertEqual(details.canonical["frames"][0]["function"], "process_order")


class TestCrossMachineStability(unittest.TestCase):
    """Mesmo módulo + função = mesmo fingerprint, independente do caminho absoluto."""

    def test_different_home_dirs_same_module_same_fingerprint(self):
        fp = _fp()
        exc = _make_exc_info()

        frames_alice = (
            _make_frame(
                "myapp.services",
                "process",
                filename="/home/alice/projects/myapp/services.py",
            ),
        )
        frames_bob = (
            _make_frame(
                "myapp.services",
                "process",
                filename="/home/bob/work/myapp/services.py",
            ),
        )

        details_alice = fp.generate(exc, frames_alice)
        details_bob = fp.generate(exc, frames_bob)

        self.assertEqual(details_alice.value, details_bob.value)

    def test_different_venv_paths_same_module_same_fingerprint(self):
        fp = _fp()
        exc = _make_exc_info()

        frames_dev = (
            _make_frame(
                "myapp.core",
                "handle",
                filename="/home/dev/.venv/lib/python3.13/site-packages/myapp/core.py",
            ),
        )
        frames_ci = (
            _make_frame(
                "myapp.core",
                "handle",
                filename="/opt/runner/.venv/lib/python3.13/site-packages/myapp/core.py",
            ),
        )

        details_dev = fp.generate(exc, frames_dev)
        details_ci = fp.generate(exc, frames_ci)

        self.assertEqual(details_dev.value, details_ci.value)

    def test_different_modules_produce_different_fingerprints(self):
        fp = _fp()
        exc = _make_exc_info()

        frames_a = (_make_frame("myapp.services", "process"),)
        frames_b = (_make_frame("myapp.models", "process"),)

        details_a = fp.generate(exc, frames_a)
        details_b = fp.generate(exc, frames_b)

        self.assertNotEqual(details_a.value, details_b.value)

    def test_different_functions_produce_different_fingerprints(self):
        fp = _fp()
        exc = _make_exc_info()

        frames_a = (_make_frame("myapp.services", "create_order"),)
        frames_b = (_make_frame("myapp.services", "delete_order"),)

        details_a = fp.generate(exc, frames_a)
        details_b = fp.generate(exc, frames_b)

        self.assertNotEqual(details_a.value, details_b.value)

    def test_absolute_path_vs_relative_different_os(self):
        """Caminhos de sistemas operacionais diferentes não afetam fingerprint quando module está presente."""
        fp = _fp()
        exc = _make_exc_info()

        frames_linux = (
            _make_frame(
                "app.api.views",
                "get_user",
                filename="/usr/local/lib/python3.13/site-packages/app/api/views.py",
            ),
        )
        frames_windows = (
            _make_frame(
                "app.api.views",
                "get_user",
                filename=r"C:\Users\user\AppData\Roaming\Python\app\api\views.py",
            ),
        )

        details_linux = fp.generate(exc, frames_linux)
        details_windows = fp.generate(exc, frames_windows)

        self.assertEqual(details_linux.value, details_windows.value)


class TestPathTailFallback(unittest.TestCase):
    """Quando module não está disponível, usa _path_tail como fallback."""

    def test_fallback_uses_last_3_components(self):
        """Quando module=None/empty, usa os últimos 3 segmentos do path."""
        fp = _fp()
        exc = _make_exc_info()

        frame_with_module = _make_frame("app.services", "run")
        frame_no_module = FrameInfo(
            filename="/a/b/c/d/e/services.py",
            line_number=10,
            function="run",
            module="",
            source_line="raise",
            locals={},
        )

        frames_with = (frame_with_module,)
        frames_without = (frame_no_module,)

        details_with = fp.generate(exc, frames_with)
        details_without = fp.generate(exc, frames_without)

        # Diferentes módulos → diferentes fingerprints
        self.assertNotEqual(details_with.value, details_without.value)

    def test_same_path_tail_cross_platform(self):
        """Dois frames com mesmo tail (últimos 3 segmentos) produzem mesmo fingerprint."""
        fp = _fp()
        exc = _make_exc_info()

        # Ambos terminam em pkg/sub/module.py → mesmo tail
        frame_a = FrameInfo(
            filename="/home/alice/projects/myapp/pkg/sub/module.py",
            line_number=10,
            function="run",
            module="",
            source_line="",
            locals={},
        )
        frame_b = FrameInfo(
            filename="/home/bob/work/myapp/pkg/sub/module.py",
            line_number=10,
            function="run",
            module="",
            source_line="",
            locals={},
        )

        details_a = fp.generate(exc, (frame_a,))
        details_b = fp.generate(exc, (frame_b,))

        self.assertEqual(details_a.value, details_b.value)


if __name__ == "__main__":
    unittest.main()
