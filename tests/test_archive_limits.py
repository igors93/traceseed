"""Validate archive limits and unsafe package paths."""

import os
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path

from traceseed import TraceSeedConfig
from traceseed.errors import IntegrityError, InvalidPackageError
from traceseed.serialization import SafeSerializer
from traceseed.storage.archive import ArchiveStorage


def _make_archive(entries: dict[str, bytes], path: str) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)


def _make_archive_with_duplicates(name: str, content: bytes, path: str) -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr(name, content)
            archive.writestr(name, b"different content")


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
        entries = {f"file_{index}.json": b"{}" for index in range(15)}
        package = self._pkg()
        _make_archive(entries, package)

        with self.assertRaises(InvalidPackageError) as context:
            self.stor.load_files(package)

        message = str(context.exception).lower()
        self.assertIn("limit", message)
        self.assertIn("15", message)
        self.assertIn("10", message)

    def test_file_too_large(self):
        entries = {"big.json": b"x" * 2000}
        package = self._pkg()
        _make_archive(entries, package)

        with self.assertRaises(InvalidPackageError) as context:
            self.stor.load_files(package)

        message = str(context.exception).lower()
        self.assertIn("big.json", message)
        self.assertIn("size limit", message)

    def test_total_size_exceeded(self):
        # Disable the compression-ratio check so the total-size limit is evaluated first.
        config = TraceSeedConfig(
            output_directory=Path(self.tmp),
            max_archive_files=10,
            max_archive_file_size=1024,
            max_archive_total_size=4096,
            max_compression_ratio=10000,
            max_manifest_size=512,
        )
        storage = ArchiveStorage(config, SafeSerializer(config))
        entries = {f"file_{index}.json": b"x" * 500 for index in range(10)}
        package = self._pkg("total_test.tseed")
        _make_archive(entries, package)

        with self.assertRaises(InvalidPackageError) as context:
            storage.load_files(package)

        self.assertIn("total", str(context.exception).lower())

    def test_absolute_path_rejected(self):
        entries = {"/etc/passwd": b"root:x:0:0"}
        package = self._pkg()
        _make_archive(entries, package)

        with self.assertRaises(InvalidPackageError) as context:
            self.stor.load_files(package)

        self.assertIn("absolute", str(context.exception).lower())

    def test_path_traversal_rejected(self):
        entries = {"../../../etc/shadow": b"sensitive"}
        package = self._pkg()
        _make_archive(entries, package)

        with self.assertRaises(InvalidPackageError) as context:
            self.stor.load_files(package)

        self.assertIn("..", str(context.exception))

    def test_duplicate_entries_rejected(self):
        package = self._pkg()
        _make_archive_with_duplicates("manifest.json", b"{}", package)

        with self.assertRaises(InvalidPackageError) as context:
            self.stor.load_files(package)

        message = str(context.exception).lower()
        self.assertIn("duplicate", message)
        self.assertIn("manifest.json", message)

    def test_valid_small_archive_passes(self):
        entries = {
            "manifest.json": b'{"format":"traceseed","format_version":1,"library_version":"0.1.0","files":["a.json"],"hashes":{}}',
            "a.json": b'{"x":1}',
        }
        package = self._pkg()
        _make_archive(entries, package)

        result = self.stor.load_files(package)

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
        package = self._pkg({"a.json": b"{}"})

        with self.assertRaises(InvalidPackageError):
            self.stor.verify(package)

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
        package = self._pkg({"manifest.json": manifest})

        with self.assertRaises(InvalidPackageError):
            self.stor.verify(package)

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
            package = self._pkg({"manifest.json": json.dumps(manifest).encode()})

            with self.assertRaises(InvalidPackageError):
                self.stor.verify(package)

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
        package = self._pkg(
            {
                "manifest.json": manifest,
                "data.json": b'{"tampered":true}',
            }
        )

        with self.assertRaises(IntegrityError):
            self.stor.verify(package)

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
        package = self._pkg(
            {
                "manifest.json": manifest,
                "unexpected.json": b"{}",
            }
        )

        with self.assertRaises(InvalidPackageError) as context:
            self.stor.verify(package)

        message = str(context.exception).lower()
        self.assertIn("archive members", message)
        self.assertIn("manifest", message)

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
        package = self._pkg({"manifest.json": manifest, "a.json": b"{}"})

        with self.assertRaises(InvalidPackageError):
            self.stor.verify(package)


if __name__ == "__main__":
    unittest.main()
