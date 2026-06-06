"""Validate manifest schema, file declarations, and integrity metadata."""

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


def _make_pkg(
    tmp: str,
    manifest: dict,
    extra_files: dict[str, bytes] | None = None,
) -> str:
    path = os.path.join(tmp, "test.tseed")
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", json.dumps(manifest).encode())
        for name, content in (extra_files or {}).items():
            archive.writestr(name, content)
    return path


def _valid_manifest(files: list[str], hashes: dict[str, str] | None = None) -> dict:
    return {
        "format": "traceseed",
        "format_version": 1,
        "library_version": "0.1.0",
        "files": files,
        "hashes": hashes or {},
    }


class TestFormatVersionValidation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        config = TraceSeedConfig(output_directory=Path(self.tmp))
        self.stor = ArchiveStorage(config, SafeSerializer(config))

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_format_version_true_rejected(self):
        """Boolean values must not pass as integers."""
        manifest = {
            "format": "traceseed",
            "format_version": True,
            "library_version": "0.1.0",
            "files": [],
            "hashes": {},
        }
        package = _make_pkg(self.tmp, manifest)

        with self.assertRaises(InvalidPackageError) as context:
            self.stor.verify(package)

        self.assertIn("bool", str(context.exception).lower())

    def test_format_version_false_rejected(self):
        manifest = {
            "format": "traceseed",
            "format_version": False,
            "library_version": "0.1.0",
            "files": [],
            "hashes": {},
        }
        package = _make_pkg(self.tmp, manifest)

        with self.assertRaises(InvalidPackageError):
            self.stor.verify(package)

    def test_format_version_string_rejected(self):
        manifest = _valid_manifest([])
        manifest["format_version"] = "1"
        package = _make_pkg(self.tmp, manifest)

        with self.assertRaises(InvalidPackageError):
            self.stor.verify(package)

    def test_format_version_unsupported_rejected(self):
        manifest = _valid_manifest([])
        manifest["format_version"] = 999
        package = _make_pkg(self.tmp, manifest)

        with self.assertRaises(InvalidPackageError) as context:
            self.stor.verify(package)

        message = str(context.exception).lower()
        self.assertIn("unsupported", message)
        self.assertIn("999", message)

    def test_format_version_1_accepted(self):
        package = _make_pkg(self.tmp, _valid_manifest([]))

        manifest = self.stor.verify(package)

        self.assertEqual(manifest["format_version"], 1)


class TestFilesHashesEquality(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        config = TraceSeedConfig(output_directory=Path(self.tmp))
        self.stor = ArchiveStorage(config, SafeSerializer(config))

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_file_with_hash_not_in_files_list_rejected(self):
        """A hash entry without a matching file declaration must be rejected."""
        content = b"{}"
        manifest = {
            "format": "traceseed",
            "format_version": 1,
            "library_version": "0.1.0",
            "files": [],
            "hashes": {"a.json": hashlib.sha256(content).hexdigest()},
        }
        package = _make_pkg(self.tmp, manifest, {"a.json": content})

        with self.assertRaises(InvalidPackageError) as context:
            self.stor.verify(package)

        self.assertIn("must match exactly", str(context.exception).lower())

    def test_file_in_list_without_hash_rejected(self):
        """Every declared payload file must have a matching hash."""
        content = b"{}"
        manifest = {
            "format": "traceseed",
            "format_version": 1,
            "library_version": "0.1.0",
            "files": ["a.json"],
            "hashes": {},
        }
        package = _make_pkg(self.tmp, manifest, {"a.json": content})

        with self.assertRaises(InvalidPackageError) as context:
            self.stor.verify(package)

        self.assertIn("must match exactly", str(context.exception).lower())

    def test_duplicate_files_in_list_rejected(self):
        manifest = {
            "format": "traceseed",
            "format_version": 1,
            "library_version": "0.1.0",
            "files": ["a.json", "a.json"],
            "hashes": {},
        }
        package = _make_pkg(self.tmp, manifest)

        with self.assertRaises(InvalidPackageError) as context:
            self.stor.verify(package)

        self.assertIn("duplicates", str(context.exception).lower())

    def test_extra_file_in_archive_rejected(self):
        content = b"{}"
        manifest = _valid_manifest([])
        package = _make_pkg(self.tmp, manifest, {"surprise.json": content})

        with self.assertRaises(InvalidPackageError) as context:
            self.stor.verify(package)

        message = str(context.exception).lower()
        self.assertIn("archive members", message)
        self.assertIn("manifest", message)

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
        package = _make_pkg(self.tmp, manifest)

        with self.assertRaises(InvalidPackageError) as context:
            self.stor.verify(package)

        message = str(context.exception).lower()
        self.assertIn("archive members", message)
        self.assertIn("manifest", message)

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
        package = _make_pkg(self.tmp, manifest, {"data.json": content})

        result = self.stor.verify(package)

        self.assertEqual(result["format"], "traceseed")


class TestManifestStructure(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        config = TraceSeedConfig(output_directory=Path(self.tmp))
        self.stor = ArchiveStorage(config, SafeSerializer(config))

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_manifest_must_be_object(self):
        path = os.path.join(self.tmp, "arr.tseed")
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("manifest.json", json.dumps([1, 2, 3]))

        with self.assertRaises(InvalidPackageError) as context:
            self.stor.verify(path)

        self.assertIn("json object", str(context.exception).lower())

    def test_library_version_must_be_non_empty_string(self):
        for bad_value in (None, "", 1, True):
            manifest = _valid_manifest([])
            manifest["library_version"] = bad_value
            package = _make_pkg(self.tmp, manifest)

            with self.assertRaises(InvalidPackageError):
                self.stor.verify(package)

    def test_files_must_be_list_of_strings(self):
        manifest = _valid_manifest([])
        manifest["files"] = {"a": 1}
        package = _make_pkg(self.tmp, manifest)

        with self.assertRaises(InvalidPackageError):
            self.stor.verify(package)

    def test_hashes_must_be_object(self):
        manifest = _valid_manifest([])
        manifest["hashes"] = [1, 2]
        package = _make_pkg(self.tmp, manifest)

        with self.assertRaises(InvalidPackageError):
            self.stor.verify(package)

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
        package = _make_pkg(
            self.tmp,
            manifest,
            {"data.json": b'{"tampered": true}'},
        )

        with self.assertRaises(IntegrityError):
            self.stor.verify(package)


if __name__ == "__main__":
    unittest.main()
