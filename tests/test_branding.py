from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

import traceseed
from traceseed import TraceSeedConfig, capture_exception
from traceseed.serialization import SafeSerializer


class BrandingTests(unittest.TestCase):
    def test_public_package_and_config_use_traceseed_name(self) -> None:
        self.assertEqual(traceseed.__name__, "traceseed")
        self.assertEqual(traceseed.__version__, "0.1.0")
        self.assertEqual(TraceSeedConfig().output_directory, Path(".traceseeds"))

    def test_old_top_level_package_is_not_exposed(self) -> None:
        old_package = "fail" + "print"
        self.assertIsNone(importlib.util.find_spec(old_package))

    def test_archive_uses_tseed_extension_and_traceseed_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            config = TraceSeedConfig(output_directory=Path(temporary_directory))
            try:
                raise RuntimeError("branding check")
            except RuntimeError as error:
                result = capture_exception(error, config=config, strict=True)

            path = Path(result.location)
            self.assertEqual(path.suffix, ".tseed")
            with zipfile.ZipFile(path, "r") as archive:
                manifest = json.loads(archive.read("manifest.json"))
            self.assertEqual(manifest["format"], "traceseed")

    def test_serialization_marker_uses_traceseed_namespace(self) -> None:
        encoded = SafeSerializer(TraceSeedConfig()).encode(Path("example"))
        self.assertEqual(encoded["__traceseed_type__"], "path")
        old_marker = "__" + "fail" + "print_type__"
        self.assertNotIn(old_marker, encoded)


class BrandingFileScanTests(unittest.TestCase):
    """Varre arquivos de texto do projeto procurando referências antigas."""

    _TEXT_EXTENSIONS = {".py", ".md", ".toml", ".cfg", ".ini", ".txt", ".yml", ".yaml", ".rst"}
    _SKIP_DIRS = {"__pycache__", ".git", ".eggs", "traceseed.egg-info", "node_modules", ".venv"}
    _OLD_NAMES = ("failprint", "Failprint", "FailprintConfig", ".fprint")

    def test_no_old_branding_in_source_files(self):
        root = Path(__file__).parent.parent
        this_file = Path(__file__).resolve()
        violations = []
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if path.resolve() == this_file:
                continue  # O próprio arquivo contém os nomes por necessidade
            if any(skip in path.parts for skip in self._SKIP_DIRS):
                continue
            if path.suffix not in self._TEXT_EXTENSIONS:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for old_name in self._OLD_NAMES:
                if old_name in text:
                    rel = path.relative_to(root)
                    violations.append(f"{rel}: contém '{old_name}'")

        if violations:
            self.fail("Referências antigas encontradas:\n" + "\n".join(sorted(violations)))


if __name__ == "__main__":
    unittest.main()
