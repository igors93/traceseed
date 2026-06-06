from __future__ import annotations

from dataclasses import dataclass

import pytest

from traceseed import CallableInfo, MemoryStorage, TraceSeedConfig, capture_exception

from . import replay_targets


@dataclass
class TwoRequiredFields:
    first: int
    second: int


def _generate_replay(argument, *, config: TraceSeedConfig):
    storage = MemoryStorage()
    result = capture_exception(
        RuntimeError("failure"),
        config=config,
        callable_info=CallableInfo(replay_targets.__name__, "echo", True),
        replay_arguments=(argument,),
        replay_keyword_arguments={},
        storage=storage,
        strict=True,
    )
    assert result is not None
    assert storage.extras
    return storage.extras[0]["replay"]


def test_truncated_string_disables_replay():
    replay = _generate_replay(
        "x" * 100,
        config=TraceSeedConfig(max_value_length=32),
    )
    assert replay["replayable"] is False
    assert "truncat" in replay["reason"].lower()


def test_truncated_bytes_disable_replay():
    replay = _generate_replay(
        b"x" * 100,
        config=TraceSeedConfig(max_value_length=32),
    )
    assert replay["replayable"] is False


@pytest.mark.parametrize(
    "argument",
    [
        list(range(10)),
        tuple(range(10)),
        set(range(10)),
        frozenset(range(10)),
        {str(index): index for index in range(10)},
    ],
)
def test_truncated_collections_disable_replay(argument):
    replay = _generate_replay(
        argument,
        config=TraceSeedConfig(max_collection_items=2),
    )
    assert replay["replayable"] is False


def test_truncated_dataclass_disables_replay():
    replay = _generate_replay(
        TwoRequiredFields(1, 2),
        config=TraceSeedConfig(max_collection_items=1),
    )
    assert replay["replayable"] is False


def test_replay_payload_never_marks_a_lossy_encoding_as_replayable():
    lossy_arguments = [
        "x" * 100,
        b"x" * 100,
        list(range(10)),
        {str(index): index for index in range(10)},
        TwoRequiredFields(1, 2),
    ]
    config = TraceSeedConfig(max_value_length=32, max_collection_items=1)
    for argument in lossy_arguments:
        replay = _generate_replay(argument, config=config)
        assert replay["replayable"] is False, (
            f"lossy value {type(argument).__name__} was incorrectly marked replayable"
        )
