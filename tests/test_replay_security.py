"""Segurança do replay: argumentos brutos nunca persistidos, replay desabilitado quando redigido."""

from __future__ import annotations

import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from traceseed import TraceSeedConfig, capture_exception
from traceseed.errors import ReplayError
from traceseed.models import CallableInfo
from traceseed.replay import ReplayRunner
from traceseed.serialization import SafeSerializer
from traceseed.storage import ArchiveStorage, MemoryStorage


class TestReplayArgsSecurity(unittest.TestCase):
    """Argumentos brutos de replay nunca aparecem em nenhum arquivo do .tseed."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def _capture_with_secret(self, secret: str) -> str:
        """Captura uma exceção com um segredo em argumento posicional."""
        cfg = TraceSeedConfig(output_directory=Path(self.tmp))
        stor = ArchiveStorage(cfg, SafeSerializer(cfg))
        try:
            raise RuntimeError("test error")
        except RuntimeError as exc:
            result = capture_exception(
                exc,
                callable_info=CallableInfo("tests.replay_targets", "add", True),
                replay_arguments=(secret, 2),
                replay_keyword_arguments={},
                config=cfg,
                storage=stor,
                strict=True,
            )
        return result.location  # type: ignore[return-value]

    def test_password_in_positional_arg_not_in_zip_bytes(self):
        secret = "super-secret-password-replay-12345"
        # Add to redact_fields via default pattern approach — use a sensitive key name
        cfg = TraceSeedConfig(output_directory=Path(self.tmp))
        stor = ArchiveStorage(cfg, SafeSerializer(cfg))
        try:
            raise RuntimeError("test")
        except RuntimeError as exc:
            result = capture_exception(
                exc,
                callable_info=CallableInfo("tests.replay_targets", "add", True),
                replay_arguments=({"password": secret},),
                replay_keyword_arguments={},
                config=cfg,
                storage=stor,
                strict=True,
            )
        path = result.location  # type: ignore[union-attr]
        raw = Path(path).read_bytes()
        self.assertNotIn(secret.encode(), raw)

    def test_token_in_kwargs_not_in_zip_bytes(self):
        secret = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        cfg = TraceSeedConfig(output_directory=Path(self.tmp))
        stor = ArchiveStorage(cfg, SafeSerializer(cfg))
        try:
            raise RuntimeError("test")
        except RuntimeError as exc:
            result = capture_exception(
                exc,
                callable_info=CallableInfo("tests.replay_targets", "add", True),
                replay_arguments=(1,),
                replay_keyword_arguments={"token": secret},
                config=cfg,
                storage=stor,
                strict=True,
            )
        path = result.location  # type: ignore[union-attr]
        raw = Path(path).read_bytes()
        self.assertNotIn(b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", raw)

    def test_replay_disabled_when_arg_redacted(self):
        """replay.json deve declarar replayable=False quando argumento é redigido."""
        storage = MemoryStorage()
        try:
            raise RuntimeError("test")
        except RuntimeError as exc:
            capture_exception(
                exc,
                callable_info=CallableInfo("tests.replay_targets", "add", True),
                replay_arguments=({"api_key": "secret-key-value"},),
                replay_keyword_arguments={},
                storage=storage,
            )
        replay = storage.extras[0].get("replay")
        self.assertIsNotNone(replay)
        self.assertFalse(replay["replayable"])
        self.assertNotIn("secret-key-value", str(replay))

    def test_replay_disabled_when_arg_has_bearer_token(self):
        """Bearer token em argumento desabilita replay."""
        storage = MemoryStorage()
        try:
            raise RuntimeError("test")
        except RuntimeError as exc:
            capture_exception(
                exc,
                callable_info=CallableInfo("tests.replay_targets", "add", True),
                replay_arguments=("Bearer supersecrettoken123",),
                replay_keyword_arguments={},
                storage=storage,
            )
        replay = storage.extras[0].get("replay")
        self.assertIsNotNone(replay)
        self.assertFalse(replay["replayable"])

    def test_replay_enabled_with_safe_args(self):
        """Argumentos sem segredos devem manter replay habilitado."""
        storage = MemoryStorage()
        try:
            raise RuntimeError("test")
        except RuntimeError as exc:
            capture_exception(
                exc,
                callable_info=CallableInfo("tests.replay_targets", "add", True),
                replay_arguments=(2,),
                replay_keyword_arguments={"b": 3},
                storage=storage,
            )
        replay = storage.extras[0].get("replay")
        self.assertIsNotNone(replay)
        self.assertTrue(replay.get("replayable", True))

    def test_raw_args_not_in_record_json(self):
        """record.json não deve conter replay_arguments nem replay_keyword_arguments."""
        storage = MemoryStorage()
        secret = "raw-secret-in-replay-args"
        try:
            raise RuntimeError("test")
        except RuntimeError as exc:
            capture_exception(
                exc,
                callable_info=CallableInfo("tests.replay_targets", "add", True),
                replay_arguments=({"password": secret},),
                replay_keyword_arguments={},
                storage=storage,
            )
        record_json = json.dumps(storage.extras[0])
        self.assertNotIn(secret, record_json)
        # FailureRecord não deve ter replay_arguments nos campos
        record = storage.records[0]
        self.assertFalse(hasattr(record, "replay_arguments"))

    def test_runner_raises_on_replayable_false(self):
        """ReplayRunner.run() deve lançar ReplayError se replay.json contém replayable=false."""
        cfg = TraceSeedConfig(output_directory=Path(self.tmp))
        stor = ArchiveStorage(cfg, SafeSerializer(cfg))
        try:
            raise RuntimeError("test")
        except RuntimeError as exc:
            result = capture_exception(
                exc,
                callable_info=CallableInfo("tests.replay_targets", "add", True),
                replay_arguments=({"password": "secret"},),
                replay_keyword_arguments={},
                config=cfg,
                storage=stor,
                strict=True,
            )
        path = result.location  # type: ignore[union-attr]
        runner = ReplayRunner(cfg)
        with self.assertRaises(ReplayError) as ctx:
            runner.run(path, allow_code_execution=True)
        self.assertIn("desabilitado", str(ctx.exception))

    def test_runner_executes_safe_replay(self):
        """ReplayRunner.run() deve funcionar com argumentos seguros."""
        cfg = TraceSeedConfig(output_directory=Path(self.tmp))
        stor = ArchiveStorage(cfg, SafeSerializer(cfg))
        try:
            raise RuntimeError("test")
        except RuntimeError as exc:
            result = capture_exception(
                exc,
                callable_info=CallableInfo("tests.replay_targets", "add", True),
                replay_arguments=(2,),
                replay_keyword_arguments={"b": 3},
                config=cfg,
                storage=stor,
                strict=True,
            )
        path = result.location  # type: ignore[union-attr]
        runner = ReplayRunner(cfg)
        value = runner.run(path, allow_code_execution=True)
        self.assertEqual(value, 5)

    def test_replay_blocked_without_hashes(self):
        """Replay deve ser bloqueado quando include_package_hashes=False."""
        cfg = TraceSeedConfig(
            output_directory=Path(self.tmp),
            include_package_hashes=False,
        )
        stor = ArchiveStorage(cfg, SafeSerializer(cfg))
        try:
            raise RuntimeError("test")
        except RuntimeError as exc:
            result = capture_exception(
                exc,
                callable_info=CallableInfo("tests.replay_targets", "add", True),
                replay_arguments=(2,),
                replay_keyword_arguments={"b": 3},
                config=cfg,
                storage=stor,
                strict=True,
            )
        path = result.location  # type: ignore[union-attr]
        # replay.json não deve ter sido incluído (hashes desabilitados)
        with zipfile.ZipFile(path) as zf:
            self.assertNotIn("replay.json", zf.namelist())


class TestManifestReplayHashEnforcement(unittest.TestCase):
    """Replay bloqueado quando replay.json não tem hash."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_empty_hashes_blocks_replay(self):
        # files=[] e hashes={} passam na validação estrutural; o bloco
        # _check_replay_hash() detecta hashes vazio e levanta ReplayError.
        manifest = json.dumps(
            {
                "format": "traceseed",
                "format_version": 1,
                "library_version": "0.1.0",
                "files": [],
                "hashes": {},  # vazio — bloqueia replay
            }
        ).encode()
        path = Path(self.tmp) / "no_hashes.tseed"
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("manifest.json", manifest)
        runner = ReplayRunner()
        with self.assertRaises(ReplayError):
            runner.run(str(path), allow_code_execution=True)

    def test_replay_json_without_hash_blocks_replay(self):
        import hashlib

        summary = b"{}"
        # summary.json tem hash, mas replay.json não
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
        path = Path(self.tmp) / "no_replay_hash.tseed"
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("manifest.json", manifest)
            zf.writestr("summary.json", summary)
            # replay.json adicionado mas não declarado no manifesto
        runner = ReplayRunner()
        with self.assertRaises(ReplayError):
            runner.run(str(path), allow_code_execution=True)


if __name__ == "__main__":
    unittest.main()
