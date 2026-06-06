"""Proteção contra ZIP bomb e caminhos inseguros em pacotes .tseed."""

import os
import tempfile
import unittest
import zipfile
from pathlib import Path

from traceseed import TraceSeedConfig
from traceseed.errors import IntegrityError, InvalidPackageError
from traceseed.serialization import SafeSerializer
from traceseed.storage.archive import ArchiveStorage


def _make_archive(entries: dict[str, bytes], path: str) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, content in entries.items():
            zf.writestr(name, content)


def _make_archive_with_duplicates(name: str, content: bytes, path: str) -> None:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr(name, content)
        zf.writestr(name, b"outro conteudo")


class TestArchiveLimits(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.cfg = TraceSeedConfig(
            output_directory=Path(self.tmp),
            max_archive_files=10,
            max_archive_file_size=1024,
            max_archive_total_size=4096,
            max_compression_ratio=10,
            max_manifest_size=512,
        )
        self.ser = SafeSerializer(self.cfg)
        self.stor = ArchiveStorage(self.cfg, self.ser)

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def _pkg(self, name="test.tseed"):
        return os.path.join(self.tmp, name)

    def test_too_many_files(self):
        entries = {f"file_{i}.json": b"{}" for i in range(15)}
        pkg = self._pkg()
        _make_archive(entries, pkg)
        with self.assertRaises(InvalidPackageError) as ctx:
            self.stor.load_files(pkg)
        self.assertIn("limite", str(ctx.exception).lower())

    def test_file_too_large(self):
        entries = {"big.json": b"x" * 2000}
        pkg = self._pkg()
        _make_archive(entries, pkg)
        with self.assertRaises(InvalidPackageError) as ctx:
            self.stor.load_files(pkg)
        self.assertIn("grande", str(ctx.exception).lower())

    def test_total_size_exceeded(self):
        # Usa config sem limite de compressão para que o total seja checado primeiro
        cfg = TraceSeedConfig(
            output_directory=Path(self.tmp),
            max_archive_files=10,
            max_archive_file_size=1024,
            max_archive_total_size=4096,
            max_compression_ratio=10000,  # alto para não disparar antes do total
        )
        stor = ArchiveStorage(cfg, SafeSerializer(cfg))
        entries = {f"file_{i}.json": b"x" * 500 for i in range(10)}
        pkg = self._pkg("total_test.tseed")
        _make_archive(entries, pkg)
        with self.assertRaises(InvalidPackageError) as ctx:
            stor.load_files(pkg)
        self.assertIn("total", str(ctx.exception).lower())

    def test_absolute_path_rejected(self):
        entries = {"/etc/passwd": b"root:x:0:0"}
        pkg = self._pkg()
        _make_archive(entries, pkg)
        with self.assertRaises(InvalidPackageError) as ctx:
            self.stor.load_files(pkg)
        self.assertIn("absolut", str(ctx.exception).lower())

    def test_path_traversal_rejected(self):
        entries = {"../../../etc/shadow": b"sensitive"}
        pkg = self._pkg()
        _make_archive(entries, pkg)
        with self.assertRaises(InvalidPackageError) as ctx:
            self.stor.load_files(pkg)
        self.assertIn("..", str(ctx.exception))

    def test_duplicate_entries_rejected(self):
        pkg = self._pkg()
        _make_archive_with_duplicates("manifest.json", b"{}", pkg)
        with self.assertRaises(InvalidPackageError) as ctx:
            self.stor.load_files(pkg)
        self.assertIn("duplicada", str(ctx.exception).lower())

    def test_valid_small_archive_passes(self):
        entries = {
            "manifest.json": b'{"format":"traceseed","format_version":1,"library_version":"0.1.0","files":["a.json"],"hashes":{}}',
            "a.json": b'{"x":1}',
        }
        pkg = self._pkg()
        _make_archive(entries, pkg)
        result = self.stor.load_files(pkg)
        self.assertIn("manifest.json", result)


class TestVerifyManifest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.cfg = TraceSeedConfig(output_directory=Path(self.tmp))
        self.ser = SafeSerializer(self.cfg)
        self.stor = ArchiveStorage(self.cfg, self.ser)

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def _pkg(self, entries):
        path = os.path.join(self.tmp, "test.tseed")
        _make_archive(entries, path)
        return path

    def test_missing_manifest_raises(self):
        pkg = self._pkg({"a.json": b"{}"})
        with self.assertRaises(InvalidPackageError):
            self.stor.verify(pkg)

    def test_unknown_format_raises(self):
        import json

        manifest = json.dumps(
            {
                "format": "unknown",
                "format_version": 1,
                "library_version": "0.1",
                "files": [],
                "hashes": {},
            }
        ).encode()
        pkg = self._pkg({"manifest.json": manifest})
        with self.assertRaises(InvalidPackageError):
            self.stor.verify(pkg)

    def test_missing_required_field_raises(self):
        import json

        for missing_field in ("format_version", "library_version", "files", "hashes"):
            manifest = {
                "format": "traceseed",
                "format_version": 1,
                "library_version": "0.1.0",
                "files": [],
                "hashes": {},
            }
            del manifest[missing_field]
            pkg = self._pkg({"manifest.json": json.dumps(manifest).encode()})
            with self.assertRaises(InvalidPackageError):
                self.stor.verify(pkg)

    def test_tampered_file_raises_integrity_error(self):
        import hashlib
        import json

        content = b'{"original":true}'
        hashes = {"data.json": hashlib.sha256(content).hexdigest()}
        manifest = json.dumps(
            {
                "format": "traceseed",
                "format_version": 1,
                "library_version": "0.1.0",
                "files": ["data.json"],
                "hashes": hashes,
            }
        ).encode()
        # Arquivo com conteúdo diferente
        pkg = self._pkg({"manifest.json": manifest, "data.json": b'{"tampered":true}'})
        with self.assertRaises(IntegrityError):
            self.stor.verify(pkg)

    def test_undeclared_extra_file_raises(self):
        import json

        manifest = json.dumps(
            {
                "format": "traceseed",
                "format_version": 1,
                "library_version": "0.1.0",
                "files": [],
                "hashes": {},
            }
        ).encode()
        pkg = self._pkg({"manifest.json": manifest, "unexpected.json": b"{}"})
        with self.assertRaises(InvalidPackageError) as ctx:
            self.stor.verify(pkg)
        self.assertIn("unexpected.json", str(ctx.exception))

    def test_invalid_hash_format_raises(self):
        import json

        manifest = json.dumps(
            {
                "format": "traceseed",
                "format_version": 1,
                "library_version": "0.1.0",
                "files": ["a.json"],
                "hashes": {"a.json": "nothex"},
            }
        ).encode()
        pkg = self._pkg({"manifest.json": manifest, "a.json": b"{}"})
        with self.assertRaises(InvalidPackageError):
            self.stor.verify(pkg)


if __name__ == "__main__":
    unittest.main()
