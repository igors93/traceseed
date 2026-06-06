from __future__ import annotations

import pytest

from traceseed import MemoryStorage, capture, guard
from traceseed.config import TraceSeedConfig
from traceseed.errors import ConfigurationError, StorageError


def test_invalid_redaction_regex_is_rejected_before_capture_setup():
    with pytest.raises(ConfigurationError):
        TraceSeedConfig(redact_patterns=("(",))


def test_decorator_setup_failure_does_not_replace_original_exception(monkeypatch):
    def fail_to_build_engine(config, storage):
        raise RuntimeError("internal setup failure")

    monkeypatch.setattr("traceseed.api._build_engine", fail_to_build_engine)

    @capture(storage=MemoryStorage())
    def fail():
        raise ValueError("original-application-error")

    with pytest.raises(ValueError, match="original-application-error"):
        fail()


def test_guard_setup_failure_does_not_replace_original_exception(monkeypatch):
    def fail_to_build_engine(config, storage):
        raise RuntimeError("internal setup failure")

    monkeypatch.setattr("traceseed.api._build_engine", fail_to_build_engine)

    with (
        pytest.raises(ValueError, match="original-application-error"),
        guard(
            "operation",
            storage=MemoryStorage(),
        ),
    ):
        raise ValueError("original-application-error")


def test_invalid_storage_return_is_reported_instead_of_silent_success():
    class InvalidStorage:
        name = "invalid"

        def save(self, record, extra=None):
            return None

    @capture(storage=InvalidStorage(), strict=True)
    def fail():
        raise ValueError("original")

    with pytest.raises(StorageError) as caught:
        fail()

    assert isinstance(caught.value.__cause__, ValueError)
    assert str(caught.value.__cause__) == "original"
