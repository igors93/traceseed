from __future__ import annotations

import json

import pytest

from traceseed import TraceSeedConfig
from traceseed.errors import InvalidPackageError, ReplayError, SerializationError
from traceseed.replay import ReplayRunner
from traceseed.serialization import SafeSerializer

from . import replay_targets
from ._helpers import encoded_dict, encoded_list, write_tseed


def _safe_kwargs():
    return encoded_dict([])


def _replay_payload(*, arguments, **overrides):
    payload = {
        "replayable": True,
        "module": replay_targets.__name__,
        "qualname": "echo",
        "arguments": arguments,
        "keyword_arguments": _safe_kwargs(),
    }
    payload.update(overrides)
    return payload


def test_missing_replayable_flag_is_rejected_before_import(tmp_path, monkeypatch):
    payload = _replay_payload(arguments=encoded_list([1]))
    payload.pop("replayable")
    package = write_tseed(tmp_path / "missing-flag.tseed", {"replay.json": json.dumps(payload)})

    imported = False

    def forbidden_import(name):
        nonlocal imported
        imported = True
        raise AssertionError("module import happened before replay schema validation")

    monkeypatch.setattr("traceseed.replay.runner.importlib.import_module", forbidden_import)
    with pytest.raises(ReplayError):
        ReplayRunner().run(package, allow_code_execution=True)
    assert imported is False


@pytest.mark.parametrize("flag", [1, "true", [], {}])
def test_replayable_flag_must_be_a_real_boolean(tmp_path, flag):
    payload = _replay_payload(arguments=encoded_list([1]), replayable=flag)
    package = write_tseed(tmp_path / f"flag-{type(flag).__name__}.tseed", {"replay.json": json.dumps(payload)})
    with pytest.raises((ReplayError, InvalidPackageError)):
        ReplayRunner().run(package, allow_code_execution=True)


@pytest.mark.parametrize("missing_field", ["module", "qualname", "arguments", "keyword_arguments"])
def test_missing_replay_schema_fields_raise_controlled_error(tmp_path, missing_field):
    payload = _replay_payload(arguments=encoded_list([1]))
    payload.pop(missing_field)
    package = write_tseed(tmp_path / f"missing-{missing_field}.tseed", {"replay.json": json.dumps(payload)})

    with pytest.raises((ReplayError, InvalidPackageError)):
        ReplayRunner().run(package, allow_code_execution=True)


def test_inspect_rejects_non_object_replay_json(tmp_path):
    package = write_tseed(tmp_path / "list-replay.tseed", {"replay.json": "[]"})
    with pytest.raises((ReplayError, InvalidPackageError)):
        ReplayRunner().inspect(package)


def test_loaded_replay_payload_obeys_configured_size_limit(tmp_path):
    config = TraceSeedConfig(max_replay_payload_size=256)
    payload = _replay_payload(arguments=encoded_list(["x" * 1024]))
    package = write_tseed(tmp_path / "oversized.tseed", {"replay.json": json.dumps(payload)})

    with pytest.raises(ReplayError, match="size|large|limit|payload"):
        ReplayRunner(config).run(package, allow_code_execution=True)


@pytest.mark.parametrize(
    "encoded_value",
    [
        {"__traceseed_type__": "uuid", "value": "not-a-uuid"},
        {"__traceseed_type__": "datetime", "value": "not-a-date"},
        {"__traceseed_type__": "bytes", "encoding": "base64", "value": "A"},
        {"__traceseed_type__": "float", "value": "not-a-float-kind"},
    ],
)
def test_malformed_serialized_arguments_raise_replay_error(tmp_path, encoded_value):
    payload = _replay_payload(arguments=encoded_list([encoded_value]))
    package = write_tseed(tmp_path / "malformed-argument.tseed", {"replay.json": json.dumps(payload)})

    with pytest.raises(ReplayError):
        ReplayRunner().run(package, allow_code_execution=True)


def test_unhashable_decoded_dictionary_key_raises_replay_error(tmp_path):
    malformed_dict = encoded_dict([[encoded_list([1]), "value"]])
    payload = _replay_payload(arguments=encoded_list([malformed_dict]))
    package = write_tseed(tmp_path / "unhashable-key.tseed", {"replay.json": json.dumps(payload)})

    with pytest.raises(ReplayError):
        ReplayRunner().run(package, allow_code_execution=True)


def test_serializer_rejects_excessive_decode_depth_with_domain_error():
    serializer = SafeSerializer(TraceSeedConfig(max_depth=8))
    value = "leaf"
    for _ in range(1500):
        value = {"nested": value}

    with pytest.raises(SerializationError):
        serializer.decode(value)
