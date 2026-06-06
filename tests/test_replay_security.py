"""Validate replay redaction, integrity, and explicit execution policy."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from traceseed import TraceSeedConfig, capture_exception
from traceseed.errors import ConfigurationError, InvalidPackageError, ReplayError
from traceseed.models import CallableInfo
from traceseed.replay import ReplayRunner
from traceseed.serialization import SafeSerializer
from traceseed.storage import ArchiveStorage, MemoryStorage


def _archive_payload_bytes(path: str | Path) -> bytes:
    """Return decompressed bytes for every member in a package."""
    with zipfile.ZipFile(path) as archive:
        return b"\n".join(archive.read(name) for name in archive.namelist())


class TestReplayArgsSecurity(unittest.TestCase):
    """Replay arguments must be sanitized before persistence."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_password_in_positional_arg_not_in_package_payloads(self):
        secret = "super-secret-password-replay-12345"
        config = TraceSeedConfig(output_directory=Path(self.tmp))
        storage = ArchiveStorage(config, SafeSerializer(config))

        try:
            raise RuntimeError("test")
        except RuntimeError as error:
            result = capture_exception(
                error,
                callable_info=CallableInfo("tests.replay_targets", "add", True),
                replay_arguments=({"password": secret},),
                replay_keyword_arguments={},
                config=config,
                storage=storage,
                strict=True,
            )

        path = result.location  # type: ignore[union-attr]
        self.assertNotIn(secret.encode(), _archive_payload_bytes(path))

    def test_token_in_keyword_arguments_not_in_package_payloads(self):
        secret = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        token_value = b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        config = TraceSeedConfig(output_directory=Path(self.tmp))
        storage = ArchiveStorage(config, SafeSerializer(config))

        try:
            raise RuntimeError("test")
        except RuntimeError as error:
            result = capture_exception(
                error,
                callable_info=CallableInfo("tests.replay_targets", "add", True),
                replay_arguments=(1,),
                replay_keyword_arguments={"token": secret},
                config=config,
                storage=storage,
                strict=True,
            )

        path = result.location  # type: ignore[union-attr]
        self.assertNotIn(token_value, _archive_payload_bytes(path))

    def test_replay_disabled_when_argument_is_redacted(self):
        storage = MemoryStorage()

        try:
            raise RuntimeError("test")
        except RuntimeError as error:
            capture_exception(
                error,
                callable_info=CallableInfo("tests.replay_targets", "add", True),
                replay_arguments=({"api_key": "secret-key-value"},),
                replay_keyword_arguments={},
                storage=storage,
            )

        replay = storage.extras[0].get("replay")
        self.assertIsNotNone(replay)
        self.assertIs(replay["replayable"], False)
        self.assertNotIn("secret-key-value", str(replay))

    def test_replay_disabled_when_argument_contains_bearer_token(self):
        storage = MemoryStorage()

        try:
            raise RuntimeError("test")
        except RuntimeError as error:
            capture_exception(
                error,
                callable_info=CallableInfo("tests.replay_targets", "add", True),
                replay_arguments=("Bearer supersecrettoken123",),
                replay_keyword_arguments={},
                storage=storage,
            )

        replay = storage.extras[0].get("replay")
        self.assertIsNotNone(replay)
        self.assertIs(replay["replayable"], False)

    def test_replay_enabled_with_safe_arguments(self):
        storage = MemoryStorage()

        try:
            raise RuntimeError("test")
        except RuntimeError as error:
            capture_exception(
                error,
                callable_info=CallableInfo("tests.replay_targets", "add", True),
                replay_arguments=(2,),
                replay_keyword_arguments={"b": 3},
                storage=storage,
            )

        replay = storage.extras[0].get("replay")
        self.assertIsNotNone(replay)
        self.assertIs(replay["replayable"], True)

    def test_raw_replay_arguments_are_not_stored_on_failure_record(self):
        storage = MemoryStorage()
        secret = "raw-secret-in-replay-args"

        try:
            raise RuntimeError("test")
        except RuntimeError as error:
            capture_exception(
                error,
                callable_info=CallableInfo("tests.replay_targets", "add", True),
                replay_arguments=({"password": secret},),
                replay_keyword_arguments={},
                storage=storage,
            )

        serialized_extra = json.dumps(storage.extras[0])
        self.assertNotIn(secret, serialized_extra)
        self.assertFalse(hasattr(storage.records[0], "replay_arguments"))

    def test_runner_rejects_replayable_false(self):
        config = TraceSeedConfig(output_directory=Path(self.tmp))
        storage = ArchiveStorage(config, SafeSerializer(config))

        try:
            raise RuntimeError("test")
        except RuntimeError as error:
            result = capture_exception(
                error,
                callable_info=CallableInfo("tests.replay_targets", "add", True),
                replay_arguments=({"password": "secret"},),
                replay_keyword_arguments={},
                config=config,
                storage=storage,
                strict=True,
            )

        path = result.location  # type: ignore[union-attr]
        runner = ReplayRunner(config)
        with self.assertRaises(ReplayError) as context:
            runner.run(path, allow_code_execution=True)

        message = str(context.exception).lower()
        self.assertIn("disabled", message)
        self.assertIn("redacted or truncated", message)

    def test_runner_executes_safe_replay(self):
        config = TraceSeedConfig(output_directory=Path(self.tmp))
        storage = ArchiveStorage(config, SafeSerializer(config))

        try:
            raise RuntimeError("test")
        except RuntimeError as error:
            result = capture_exception(
                error,
                callable_info=CallableInfo("tests.replay_targets", "add", True),
                replay_arguments=(2,),
                replay_keyword_arguments={"b": 3},
                config=config,
                storage=storage,
                strict=True,
            )

        path = result.location  # type: ignore[union-attr]
        value = ReplayRunner(config).run(path, allow_code_execution=True)
        self.assertEqual(value, 5)

    def test_configuration_rejects_disabling_package_hashes(self):
        with self.assertRaises(ConfigurationError) as context:
            TraceSeedConfig(
                output_directory=Path(self.tmp),
                include_package_hashes=False,
            )

        message = str(context.exception).lower()
        self.assertIn("hashes", message)
        self.assertIn("mandatory", message)


class TestManifestReplayHashEnforcement(unittest.TestCase):
    """A replay payload must be declared and hashed by the manifest."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_replay_declared_without_hash_is_rejected(self):
        replay = json.dumps(
            {
                "replayable": True,
                "module": "tests.replay_targets",
                "qualname": "add",
                "arguments": [2],
                "keyword_arguments": {"b": 3},
            }
        ).encode()
        manifest = json.dumps(
            {
                "format": "traceseed",
                "format_version": 1,
                "library_version": "0.1.0",
                "files": ["replay.json"],
                "hashes": {},
            }
        ).encode()
        path = Path(self.tmp) / "missing_replay_hash.tseed"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("manifest.json", manifest)
            archive.writestr("replay.json", replay)

        with self.assertRaises(InvalidPackageError) as context:
            ReplayRunner().run(str(path), allow_code_execution=True)

        self.assertIn("must match exactly", str(context.exception).lower())

    def test_undeclared_replay_payload_is_rejected(self):
        summary = b"{}"
        replay = json.dumps(
            {
                "replayable": True,
                "module": "tests.replay_targets",
                "qualname": "add",
                "arguments": [2],
                "keyword_arguments": {"b": 3},
            }
        ).encode()
        hashes = {"summary.json": hashlib.sha256(summary).hexdigest()}
        manifest = json.dumps(
            {
                "format": "traceseed",
                "format_version": 1,
                "library_version": "0.1.0",
                "files": ["summary.json"],
                "hashes": hashes,
            }
        ).encode()
        path = Path(self.tmp) / "undeclared_replay.tseed"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("manifest.json", manifest)
            archive.writestr("summary.json", summary)
            archive.writestr("replay.json", replay)

        with self.assertRaises(InvalidPackageError) as context:
            ReplayRunner().run(str(path), allow_code_execution=True)

        message = str(context.exception).lower()
        self.assertIn("archive members", message)
        self.assertIn("manifest", message)


if __name__ == "__main__":
    unittest.main()
