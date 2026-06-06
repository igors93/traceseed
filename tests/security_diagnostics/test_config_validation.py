from __future__ import annotations

from pathlib import Path

import pytest

from traceseed import TraceSeedConfig
from traceseed.errors import ConfigurationError


def test_invalid_regex_is_rejected_when_configuration_is_created():
    with pytest.raises(ConfigurationError):
        TraceSeedConfig(redact_patterns=("(",))


@pytest.mark.parametrize("patterns", [None, "Bearer\\s+\\S+", (123,), [None]])
def test_redaction_patterns_must_be_a_collection_of_strings(patterns):
    with pytest.raises((ConfigurationError, TypeError)):
        TraceSeedConfig(redact_patterns=patterns)  # type: ignore[arg-type]


@pytest.mark.parametrize("fields", [None, "password", {1, "password"}, [None]])
def test_redaction_fields_must_be_a_collection_of_strings(fields):
    with pytest.raises((ConfigurationError, TypeError)):
        TraceSeedConfig(redact_fields=fields)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "field_name",
    [
        "max_value_length",
        "max_collection_items",
        "max_depth",
        "max_breadcrumbs",
        "max_frames",
        "fingerprint_frame_limit",
        "max_archive_files",
        "max_archive_file_size",
        "max_archive_total_size",
        "max_compression_ratio",
        "max_manifest_size",
        "max_exception_depth",
        "max_exception_children",
        "max_operation_length",
        "max_traceback_text_length",
        "max_replay_payload_size",
    ],
)
def test_security_limits_reject_fractional_values(field_name: str):
    with pytest.raises(ConfigurationError):
        TraceSeedConfig(**{field_name: 100.5})


@pytest.mark.parametrize(
    "field_name",
    [
        "max_value_length",
        "max_collection_items",
        "max_depth",
        "max_archive_files",
        "max_archive_file_size",
        "max_archive_total_size",
        "max_compression_ratio",
        "max_manifest_size",
        "max_exception_depth",
        "max_operation_length",
        "max_traceback_text_length",
        "max_replay_payload_size",
    ],
)
def test_security_limits_reject_bool_values(field_name: str):
    with pytest.raises(ConfigurationError):
        TraceSeedConfig(**{field_name: True})


def test_output_directory_rejects_unrelated_types():
    with pytest.raises((ConfigurationError, TypeError)):
        TraceSeedConfig(output_directory=object())  # type: ignore[arg-type]


def test_output_directory_accepts_string_and_normalizes_to_path():
    config = TraceSeedConfig(output_directory="diagnostic-output")
    assert config.output_directory == Path("diagnostic-output")


def test_filename_prefix_must_be_a_string():
    with pytest.raises((ConfigurationError, TypeError)):
        TraceSeedConfig(filename_prefix=123)  # type: ignore[arg-type]
