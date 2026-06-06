"""Validação estrita do manifesto: format_version bool, files==hashes, extras, etc."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path

from traceseed import TraceSeedConfig
from traceseed.errors import IntegrityError, InvalidPackageError
from traceseed.serialization import SafeSerializer
from traceseed.storage.archive import ArchiveStorage


def _make_pkg(tmp: str, manifest: dict, extra_files: dict[str, bytes] | None = None) -> str:
    path = os.path.join(tmp, "test.tseed")
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", json.dumps(manifest).encode())
        for name, content in (extra_files or {}).items():
            zf.writestr(name, content)
    return path


def _valid_manifest(files: list[str], hashes: dict[str, str] | None = None) -> dict:
    if hashes is None:
        hashes = {}
    return {
        "format": "traceseed",
        "format_version": 1,
        "library_version": "0.1.0",
        "files": files,
        "hashes": hashes,
    }


class TestFormatVersionValidation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        cfg = TraceSeedConfig(output_directory=Path(self.tmp))
        self.stor = ArchiveStorage(cfg, SafeSerializer(cfg))

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_format_version_true_rejected(self):
        """True é subclasse de int — deve ser explicitamente rejeitado."""
        manifest = {
            "format": "traceseed",
            "format_version": True,  # bool, não int real
            "library_version": "0.1.0",
            "files": [],
            "hashes": {},
        }
        pkg = _make_pkg(self.tmp, manifest)
        with self.assertRaises(InvalidPackageError) as ctx:
            self.stor.verify(pkg)
        self.assertIn("bool", str(ctx.exception).lower())

    def test_format_version_false_rejected(self):
        manifest = {
            "format": "traceseed",
            "format_version": False,
            "library_version": "0.1.0",
            "files": [],
            "hashes": {},
        }
        pkg = _make_pkg(self.tmp, manifest)
        with self.assertRaises(InvalidPackageError):
            self.stor.verify(pkg)

    def test_format_version_string_rejected(self):
        manifest = _valid_manifest([])
        manifest["format_version"] = "1"
        pkg = _make_pkg(self.tmp, manifest)
        with self.assertRaises(InvalidPackageError):
            self.stor.verify(pkg)

    def test_format_version_unsupported_rejected(self):
        manifest = _valid_manifest([])
        manifest["format_version"] = 999
        pkg = _make_pkg(self.tmp, manifest)
        with self.assertRaises(InvalidPackageError) as ctx:
            self.stor.verify(pkg)
        self.assertIn("suportado", str(ctx.exception).lower())

    def test_format_version_1_accepted(self):
        pkg = _make_pkg(self.tmp, _valid_manifest([]))
        manifest = self.stor.verify(pkg)
        self.assertEqual(manifest["format_version"], 1)


class TestFilesHashesEquality(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        cfg = TraceSeedConfig(output_directory=Path(self.tmp))
        self.stor = ArchiveStorage(cfg, SafeSerializer(cfg))

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_file_with_hash_not_in_files_list_rejected(self):
        """Chave em hashes que não está em files deve falhar."""
        content = b"{}"
        manifest = {
            "format": "traceseed",
            "format_version": 1,
            "library_version": "0.1.0",
            "files": [],
            "hashes": {"a.json": hashlib.sha256(content).hexdigest()},
        }
        pkg = _make_pkg(self.tmp, manifest, {"a.json": content})
        with self.assertRaises(InvalidPackageError) as ctx:
            self.stor.verify(pkg)
        self.assertIn("coincidem", str(ctx.exception).lower())

    def test_file_in_list_without_hash_rejected(self):
        """Arquivo declarado em files sem hash correspondente deve falhar."""
        content = b"{}"
        manifest = {
            "format": "traceseed",
            "format_version": 1,
            "library_version": "0.1.0",
            "files": ["a.json"],
            "hashes": {},  # sem hash para a.json
        }
        pkg = _make_pkg(self.tmp, manifest, {"a.json": content})
        with self.assertRaises(InvalidPackageError) as ctx:
            self.stor.verify(pkg)
        self.assertIn("coincidem", str(ctx.exception).lower())

    def test_duplicate_files_in_list_rejected(self):
        manifest = {
            "format": "traceseed",
            "format_version": 1,
            "library_version": "0.1.0",
            "files": ["a.json", "a.json"],
            "hashes": {},
        }
        pkg = _make_pkg(self.tmp, manifest)
        with self.assertRaises(InvalidPackageError) as ctx:
            self.stor.verify(pkg)
        self.assertIn("duplicad", str(ctx.exception).lower())

    def test_extra_file_in_archive_rejected(self):
        content = b"{}"
        manifest = _valid_manifest([])
        pkg = _make_pkg(self.tmp, manifest, {"surprise.json": content})
        with self.assertRaises(InvalidPackageError) as ctx:
            self.stor.verify(pkg)
        self.assertIn("surprise.json", str(ctx.exception))

    def test_declared_file_absent_from_archive_rejected(self):
        content = b"{}"
        hashes = {"a.json": hashlib.sha256(content).hexdigest()}
        manifest = {
            "format": "traceseed",
            "format_version": 1,
            "library_version": "0.1.0",
            "files": ["a.json"],
            "hashes": hashes,
        }
        # a.json declarado mas não adicionado ao ZIP
        pkg = _make_pkg(self.tmp, manifest)
        with self.assertRaises(InvalidPackageError) as ctx:
            self.stor.verify(pkg)
        self.assertIn("ausente", str(ctx.exception).lower())

    def test_valid_package_with_correct_hashes_passes(self):
        content = b'{"x": 1}'
        hashes = {"data.json": hashlib.sha256(content).hexdigest()}
        manifest = {
            "format": "traceseed",
            "format_version": 1,
            "library_version": "0.1.0",
            "files": ["data.json"],
            "hashes": hashes,
        }
        pkg = _make_pkg(self.tmp, manifest, {"data.json": content})
        result = self.stor.verify(pkg)
        self.assertEqual(result["format"], "traceseed")


class TestManifestStructure(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        cfg = TraceSeedConfig(output_directory=Path(self.tmp))
        self.stor = ArchiveStorage(cfg, SafeSerializer(cfg))

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_manifest_must_be_object(self):
        path = os.path.join(self.tmp, "arr.tseed")
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("manifest.json", json.dumps([1, 2, 3]))
        with self.assertRaises(InvalidPackageError) as ctx:
            self.stor.verify(path)
        self.assertIn("objeto", str(ctx.exception).lower())

    def test_library_version_must_be_non_empty_string(self):
        for bad_value in (None, "", 1, True):
            manifest = _valid_manifest([])
            manifest["library_version"] = bad_value
            pkg = _make_pkg(self.tmp, manifest)
            with self.assertRaises(InvalidPackageError):
                self.stor.verify(pkg)

    def test_files_must_be_list_of_strings(self):
        manifest = _valid_manifest([])
        manifest["files"] = {"a": 1}  # dict instead of list
        pkg = _make_pkg(self.tmp, manifest)
        with self.assertRaises(InvalidPackageError):
            self.stor.verify(pkg)

    def test_hashes_must_be_object(self):
        manifest = _valid_manifest([])
        manifest["hashes"] = [1, 2]  # list instead of dict
        pkg = _make_pkg(self.tmp, manifest)
        with self.assertRaises(InvalidPackageError):
            self.stor.verify(pkg)

    def test_tampering_detected(self):
        content = b'{"original": true}'
        hashes = {"data.json": hashlib.sha256(content).hexdigest()}
        manifest = {
            "format": "traceseed",
            "format_version": 1,
            "library_version": "0.1.0",
            "files": ["data.json"],
            "hashes": hashes,
        }
        # Arquivo diferente do hash declarado
        pkg = _make_pkg(self.tmp, manifest, {"data.json": b'{"tampered": true}'})
        with self.assertRaises(IntegrityError):
            self.stor.verify(pkg)


if __name__ == "__main__":
    unittest.main()
