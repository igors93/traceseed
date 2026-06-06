from __future__ import annotations

import re

import pytest

from traceseed import MemoryStorage, TraceSeedConfig, capture, guard
from traceseed.errors import StorageError


def test_invalid_redaction_regex_does_not_replace_original_exception_in_decorator():
    config = TraceSeedConfig(redact_patterns=("(",))

    @capture(storage=MemoryStorage(), config=config)
    def fail():
        raise ValueError("original-application-error")

    with pytest.raises(ValueError, match="original-application-error"):
        fail()


def test_invalid_redaction_regex_does_not_replace_original_exception_in_guard():
    config = TraceSeedConfig(redact_patterns=("(",))

    with pytest.raises(ValueError, match="original-application-error"), guard(
        "operation", storage=MemoryStorage(), config=config
    ):
        raise ValueError("original-application-error")


def test_capture_boundary_does_not_leak_regex_compilation_error():
    config = TraceSeedConfig(redact_patterns=("(",))

    @capture(storage=MemoryStorage(), config=config)
    def fail():
        raise RuntimeError("original")

    try:
        fail()
    except Exception as error:
        assert not isinstance(error, re.error)
        assert isinstance(error, RuntimeError)
        assert str(error) == "original"
    else:
        pytest.fail("the original exception was unexpectedly suppressed")


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
