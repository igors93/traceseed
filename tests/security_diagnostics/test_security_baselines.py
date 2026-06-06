from __future__ import annotations

import json
import os
import runpy
import zipfile

import pytest

from traceseed import TraceSeedConfig, capture_exception
from traceseed.errors import IntegrityError, ReplayError
from traceseed.replay import ReplayRunner
from traceseed.serialization import SafeSerializer
from traceseed.storage import ArchiveStorage, MemoryStorage

from . import replay_targets
from ._helpers import encoded_dict, encoded_list, rewrite_zip_member, write_tseed


def _valid_replay_payload(*, replayable=True):
    return {
        "replayable": replayable,
        "module": replay_targets.__name__,
        "qualname": "echo",
        "arguments": encoded_list(["value"]),
        "keyword_arguments": encoded_dict([]),
    }


def test_replay_requires_explicit_authorization(tmp_path):
    package = write_tseed(
        tmp_path / "replay.tseed",
        {"replay.json": json.dumps(_valid_replay_payload())},
    )
    with pytest.raises(ReplayError):
        ReplayRunner().run(package, allow_code_execution=False)


def test_replayable_false_is_rejected_before_module_import(tmp_path, monkeypatch):
    package = write_tseed(
        tmp_path / "disabled.tseed",
        {"replay.json": json.dumps(_valid_replay_payload(replayable=False))},
    )

    def forbidden_import(name):
        raise AssertionError("disabled replay imported a module")

    monkeypatch.setattr("traceseed.replay.runner.importlib.import_module", forbidden_import)
    with pytest.raises(ReplayError):
        ReplayRunner().run(package, allow_code_execution=True)


def test_tampered_replay_is_rejected_before_module_import(tmp_path, monkeypatch):
    package = write_tseed(
        tmp_path / "tampered.tseed",
        {"replay.json": json.dumps(_valid_replay_payload())},
    )
    rewrite_zip_member(
        package,
        "replay.json",
        json.dumps(_valid_replay_payload(replayable=False)),
    )

    def forbidden_import(name):
        raise AssertionError("tampered package imported a module")

    monkeypatch.setattr("traceseed.replay.runner.importlib.import_module", forbidden_import)
    with pytest.raises(IntegrityError):
        ReplayRunner().run(package, allow_code_execution=True)


def test_argv_is_not_captured_by_default(monkeypatch):
    monkeypatch.setattr("traceseed.collectors.sys.argv", ["app", "--password", "secret"])
    storage = MemoryStorage()
    result = capture_exception(RuntimeError("failure"), storage=storage, strict=True)
    assert result is not None
    assert result.record.runtime.argv == ()


def test_source_line_bearer_token_is_redacted(tmp_path):
    script = tmp_path / "source_redaction_test.py"
    script.write_text(
        "value = 'Bearer source-secret-token'\nraise RuntimeError(value)\n",
        encoding="utf-8",
    )
    try:
        runpy.run_path(script)
    except RuntimeError as error:
        storage = MemoryStorage()
        result = capture_exception(error, storage=storage, strict=True)
    assert result is not None
    source_lines = [frame.source_line for frame in result.record.frames if frame.source_line]
    assert source_lines, "the traceback should include at least one source line"
    assert all("source-secret-token" not in line for line in source_lines)


def test_generated_archive_hashes_every_payload_member(tmp_path):
    config = TraceSeedConfig(output_directory=tmp_path)
    storage = ArchiveStorage(config, SafeSerializer(config))
    result = capture_exception(RuntimeError("failure"), config=config, storage=storage, strict=True)
    assert result is not None

    with zipfile.ZipFile(result.location) as archive:
        manifest = json.loads(archive.read("manifest.json"))
        payload_names = set(archive.namelist()) - {"manifest.json"}
    assert payload_names == set(manifest["files"])
    assert payload_names == set(manifest["hashes"])


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits are not authoritative on Windows")
def test_generated_archive_is_private_to_owner_by_default(tmp_path):
    config = TraceSeedConfig(output_directory=tmp_path)
    storage = ArchiveStorage(config, SafeSerializer(config))
    result = capture_exception(RuntimeError("failure"), config=config, storage=storage, strict=True)
    assert result is not None

    mode = os.stat(result.location).st_mode & 0o777
    assert mode & 0o077 == 0
