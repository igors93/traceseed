"""Validate ZIP metadata before package content is read."""

from __future__ import annotations

import os
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path

from traceseed import TraceSeedConfig
from traceseed.errors import InvalidPackageError
from traceseed.serialization import SafeSerializer
from traceseed.storage.archive import ArchiveStorage


def _make_zip(
    path: str,
    entries: dict[str, bytes],
    compression=zipfile.ZIP_DEFLATED,
) -> None:
    with zipfile.ZipFile(path, "w", compression=compression) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)


class TestZipTypeRejection(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        config = TraceSeedConfig(output_directory=Path(self.tmp))
        self.stor = ArchiveStorage(config, SafeSerializer(config))

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def _pkg(self, name="test.tseed"):
        return os.path.join(self.tmp, name)

    def test_directory_entry_rejected(self):
        path = self._pkg()
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr(zipfile.ZipInfo("subdir/"), b"")
            archive.writestr("manifest.json", b"{}")

        with self.assertRaises(InvalidPackageError) as context:
            self.stor.load_files(path)

        message = str(context.exception).lower()
        self.assertIn("non-canonical path", message)
        self.assertIn("subdir/", message)

    def test_encrypted_entry_rejected(self):
        path = self._pkg()
        with zipfile.ZipFile(path, "w") as archive:
            info = zipfile.ZipInfo("secret.json")
            info.compress_type = zipfile.ZIP_STORED
            info.flag_bits = 0x1
            archive.writestr(info, b"{}")

        with zipfile.ZipFile(path, "r") as archive:
            encrypted = any(
                info.filename == "secret.json" and info.flag_bits & 0x1
                for info in archive.infolist()
            )
        if not encrypted:
            self.skipTest("the standard library did not preserve the encryption flag")

        with self.assertRaises(InvalidPackageError) as context:
            self.stor.load_files(path)

        self.assertIn("encrypted", str(context.exception).lower())

    def test_symlink_unix_rejected(self):
        path = self._pkg()
        with zipfile.ZipFile(path, "w") as archive:
            info = zipfile.ZipInfo("link.txt")
            info.external_attr = 0o120000 << 16
            archive.writestr(info, b"../etc/passwd")

        with self.assertRaises(InvalidPackageError) as context:
            self.stor.load_files(path)

        message = str(context.exception).lower()
        self.assertIn("non-regular", message)
        self.assertIn("link.txt", message)

    def test_absolute_unix_path_rejected(self):
        path = self._pkg()
        _make_zip(path, {"/etc/passwd": b"root"})

        with self.assertRaises(InvalidPackageError) as context:
            self.stor.load_files(path)

        self.assertIn("absolute", str(context.exception).lower())

    def test_absolute_windows_path_rejected(self):
        path = self._pkg()
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("C:/Windows/system32/evil.exe", b"evil")

        with self.assertRaises(InvalidPackageError) as context:
            self.stor.load_files(path)

        self.assertIn("absolute", str(context.exception).lower())

    def test_path_traversal_rejected(self):
        path = self._pkg()
        _make_zip(path, {"../../etc/shadow": b"sensitive"})

        with self.assertRaises(InvalidPackageError) as context:
            self.stor.load_files(path)

        self.assertIn("..", str(context.exception))

    def test_empty_filename_rejected(self):
        path = self._pkg()
        try:
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr(zipfile.ZipInfo(""), b"data")
        except Exception as error:
            self.skipTest(f"the standard library rejected the fixture: {error}")

        with self.assertRaises(InvalidPackageError):
            self.stor.load_files(path)

    def test_duplicate_entries_rejected(self):
        path = self._pkg()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("file.json", b"first")
                archive.writestr("file.json", b"second")

        with self.assertRaises(InvalidPackageError) as context:
            self.stor.load_files(path)

        message = str(context.exception).lower()
        self.assertIn("duplicate", message)
        self.assertIn("file.json", message)

    def test_too_many_files_rejected(self):
        config = TraceSeedConfig(
            output_directory=Path(self.tmp),
            max_archive_files=3,
            max_manifest_size=512,
        )
        storage = ArchiveStorage(config, SafeSerializer(config))
        path = self._pkg("many.tseed")
        entries = {f"file_{index}.json": b"{}" for index in range(10)}
        _make_zip(path, entries)

        with self.assertRaises(InvalidPackageError) as context:
            storage.load_files(path)

        message = str(context.exception).lower()
        self.assertIn("limit", message)
        self.assertIn("10", message)
        self.assertIn("3", message)

    def test_compression_ratio_rejected(self):
        config = TraceSeedConfig(
            output_directory=Path(self.tmp),
            max_archive_file_size=50 * 1024 * 1024,
            max_archive_total_size=200 * 1024 * 1024,
            max_compression_ratio=5,
            max_manifest_size=512 * 1024,
        )
        storage = ArchiveStorage(config, SafeSerializer(config))
        path = self._pkg("bomb.tseed")
        _make_zip(path, {"bomb.json": b"a" * 100_000})

        with self.assertRaises(InvalidPackageError) as context:
            storage.load_files(path)

        message = str(context.exception).lower()
        self.assertIn("compression ratio", message)
        self.assertIn("bomb.json", message)

    def test_file_size_limit_rejected(self):
        config = TraceSeedConfig(
            output_directory=Path(self.tmp),
            max_archive_file_size=100,
            max_archive_total_size=1000,
            max_manifest_size=100,
        )
        storage = ArchiveStorage(config, SafeSerializer(config))
        path = self._pkg("big.tseed")
        _make_zip(path, {"big.json": b"x" * 200})

        with self.assertRaises(InvalidPackageError):
            storage.load_files(path)

    def test_valid_package_passes(self):
        import hashlib
        import json

        content = b'{"ok": true}'
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
        path = self._pkg("valid.tseed")
        _make_zip(path, {"manifest.json": manifest, "data.json": content})

        result = self.stor.load_files(path)

        self.assertIn("data.json", result)
        self.assertIn("manifest.json", result)


if __name__ == "__main__":
    unittest.main()
