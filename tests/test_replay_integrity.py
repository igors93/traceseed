"""Ensure package integrity is verified before any replay code executes."""

import hashlib
import json
import os
import tempfile
import unittest
import zipfile

from traceseed.errors import IntegrityError, InvalidPackageError, ReplayError
from traceseed.replay.runner import ReplayRunner


def _make_valid_replay_package(tmp: str) -> str:
    """Create a replay package with valid hashes."""
    replay_data = json.dumps(
        {
            "module": "tests.replay_targets",
            "qualname": "add_numbers",
            "arguments": [1, 2],
            "keyword_arguments": {},
        }
    ).encode()

    files = {
        "manifest.json": b"",
        "replay.json": replay_data,
        "summary.json": b"{}",
    }
    hashes = {
        name: hashlib.sha256(content).hexdigest()
        for name, content in files.items()
        if name != "manifest.json"
    }
    manifest = json.dumps(
        {
            "format": "traceseed",
            "format_version": 1,
            "library_version": "0.1.0",
            "files": [name for name in files if name != "manifest.json"],
            "hashes": hashes,
        }
    ).encode()
    files["manifest.json"] = manifest

    path = os.path.join(tmp, "valid_replay.tseed")
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return path


def _tamper_replay_json(source: str, destination: str) -> None:
    """Copy a package and replace replay.json without updating its hash."""
    with zipfile.ZipFile(source, "r") as archive:
        original = {name: archive.read(name) for name in archive.namelist()}

    original["replay.json"] = json.dumps(
        {
            "module": "os",
            "qualname": "system",
            "arguments": ["echo PWNED"],
            "keyword_arguments": {},
        }
    ).encode()

    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in original.items():
            archive.writestr(name, content)


class TestReplayIntegrity(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.runner = ReplayRunner()

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_tampered_replay_raises_integrity_error(self):
        valid = _make_valid_replay_package(self.tmp)
        tampered = os.path.join(self.tmp, "tampered.tseed")
        _tamper_replay_json(valid, tampered)

        with self.assertRaises(IntegrityError):
            self.runner.run(tampered, allow_code_execution=True)

    def test_inspect_also_verifies_integrity(self):
        valid = _make_valid_replay_package(self.tmp)
        tampered = os.path.join(self.tmp, "tampered_inspect.tseed")
        _tamper_replay_json(valid, tampered)

        with self.assertRaises(IntegrityError):
            self.runner.inspect(tampered)

    def test_run_without_allow_raises(self):
        valid = _make_valid_replay_package(self.tmp)

        with self.assertRaises(ReplayError) as context:
            self.runner.run(valid)

        message = str(context.exception).lower()
        self.assertIn("authorization", message)
        self.assertIn("application code", message)

    def test_package_without_replay_json_raises(self):
        manifest = json.dumps(
            {
                "format": "traceseed",
                "format_version": 1,
                "library_version": "0.1.0",
                "files": [],
                "hashes": {},
            }
        ).encode()
        path = os.path.join(self.tmp, "no_replay.tseed")
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("manifest.json", manifest)

        with self.assertRaises(ReplayError):
            self.runner.inspect(path)

    def test_missing_manifest_raises_before_import(self):
        path = os.path.join(self.tmp, "no_manifest.tseed")
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr(
                "replay.json",
                json.dumps(
                    {
                        "module": "os",
                        "qualname": "system",
                        "arguments": ["echo hi"],
                        "keyword_arguments": {},
                    }
                ),
            )

        with self.assertRaises(InvalidPackageError):
            self.runner.run(path, allow_code_execution=True)


if __name__ == "__main__":
    unittest.main()
