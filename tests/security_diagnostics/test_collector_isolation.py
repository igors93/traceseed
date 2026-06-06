from __future__ import annotations

from traceseed import MemoryStorage, TraceSeedConfig
from traceseed.collectors import CollectorRegistry
from traceseed.engine import CaptureEngine
from traceseed.models import CaptureContext


def _capture_with(collectors):
    storage = MemoryStorage()
    engine = CaptureEngine(
        TraceSeedConfig(),
        collectors=CollectorRegistry(list(collectors)),
        storage=storage,
    )
    result = engine.capture(RuntimeError("failure"), CaptureContext())
    return result, storage


def test_broken_collector_name_does_not_break_entire_capture():
    class BrokenNameCollector:
        @property
        def name(self):
            raise RuntimeError("broken collector name")

        def collect(self, exception, context, config):
            raise RuntimeError("collector failed")

    class GoodCollector:
        name = "good"

        def collect(self, exception, context, config):
            return {"good_value": 42}

    result, storage = _capture_with([BrokenNameCollector(), GoodCollector()])

    assert result.capture_error is None
    assert storage.records
    assert result.record.extensions["good_value"] == 42
    assert result.record.collector_errors


def test_non_string_extension_key_is_isolated_to_its_collector():
    class InvalidKeyCollector:
        name = "invalid-key"

        def collect(self, exception, context, config):
            return {1: "value"}

    class GoodCollector:
        name = "good"

        def collect(self, exception, context, config):
            return {"good_value": 42}

    result, storage = _capture_with([InvalidKeyCollector(), GoodCollector()])

    assert result.capture_error is None
    assert storage.records
    assert result.record.extensions["good_value"] == 42
    assert any(
        error["collector"] == "invalid-key"
        for error in result.record.collector_errors
    )


def test_collectors_cannot_silently_overwrite_each_others_results():
    class FirstCollector:
        name = "first"

        def collect(self, exception, context, config):
            return {"shared": "first-value"}

    class SecondCollector:
        name = "second"

        def collect(self, exception, context, config):
            return {"shared": "second-value"}

    result, _ = _capture_with([FirstCollector(), SecondCollector()])

    extensions = result.record.extensions
    assert "first" in extensions and "second" in extensions
    assert extensions["first"]["shared"] == "first-value"
    assert extensions["second"]["shared"] == "second-value"


def test_collector_returning_non_dict_is_reported_not_silently_ignored():
    class InvalidCollector:
        name = "invalid-return"

        def collect(self, exception, context, config):
            return ["not", "a", "dict"]

    result, storage = _capture_with([InvalidCollector()])

    assert result.capture_error is None
    assert storage.records
    assert any(
        error["collector"] == "invalid-return"
        for error in result.record.collector_errors
    )
