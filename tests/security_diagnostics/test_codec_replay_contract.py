from __future__ import annotations

from dataclasses import dataclass

import pytest

from traceseed import (
    CallableInfo,
    TraceSeedConfig,
    capture_exception,
    register_codec,
    unregister_codec,
)
from traceseed.errors import SerializationError
from traceseed.replay import ReplayRunner
from traceseed.serialization import SafeSerializer
from traceseed.storage import ArchiveStorage

from . import replay_targets


@dataclass
class Box:
    value: int


class BoxCodec:
    type_name = "security-diagnostic-box"

    def can_encode(self, value):
        return isinstance(value, Box)

    def encode(self, value, serializer):
        return value.value

    def decode(self, value, serializer):
        return Box(value)


def test_globally_registered_codec_round_trips_through_replay_runner(tmp_path):
    register_codec(BoxCodec())
    try:
        config = TraceSeedConfig(output_directory=tmp_path)
        storage = ArchiveStorage(config, SafeSerializer(config))
        result = capture_exception(
            RuntimeError("failure"),
            config=config,
            callable_info=CallableInfo(replay_targets.__name__, "echo", True),
            replay_arguments=(Box(7),),
            replay_keyword_arguments={},
            storage=storage,
            strict=True,
        )
        assert result is not None
        replayed = ReplayRunner(config).run(result.location, allow_code_execution=True)
        assert replayed == Box(7)
    finally:
        unregister_codec(BoxCodec.type_name)


def test_safe_serializer_rejects_duplicate_codec_type_names():
    serializer = SafeSerializer(TraceSeedConfig())
    serializer.register_codec(BoxCodec())
    with pytest.raises(ValueError, match="type_name|registered|duplicate"):
        serializer.register_codec(BoxCodec())


def test_codec_decode_failure_is_wrapped_as_serialization_error():
    class BrokenDecodeCodec:
        type_name = "broken-decode"

        def can_encode(self, value):
            return False

        def encode(self, value, serializer):
            return value

        def decode(self, value, serializer):
            raise RuntimeError("codec implementation failed")

    serializer = SafeSerializer(TraceSeedConfig())
    serializer.register_codec(BrokenDecodeCodec())
    encoded = {"__traceseed_type__": "broken-decode", "value": 1}

    with pytest.raises(SerializationError):
        serializer.decode(encoded)
