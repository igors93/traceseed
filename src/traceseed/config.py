"""Immutable and validated TraceSeed configuration."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

from .errors import ConfigurationError

_DEFAULT_REDACT_FIELDS = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "access_token",
        "refresh_token",
        "private_key",
        "authorization",
        "auth",
        "credential",
        "credentials",
        "ssn",
        "cpf",
        "cnpj",
        "credit_card",
        "card",
        "card_number",
        "cvv",
        "pin",
    }
)

_DEFAULT_REDACT_PATTERNS = (
    r"Bearer\s+\S+",
    r"\b\d{4}[\s-]\d{4}[\s-]\d{4}[\s-]\d{4}\b",
)

_INTEGER_LIMITS = (
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
)

_BOOLEAN_FIELDS = (
    "normalize_exception_messages",
    "capture_arguments",
    "capture_locals",
    "capture_argv",
    "capture_cwd",
    "capture_threads",
    "re_raise",
    "include_package_hashes",
    "write_pretty_json",
)


@dataclass(frozen=True, slots=True)
class TraceSeedConfig:
    output_directory: Path = field(default_factory=lambda: Path(".traceseeds"))
    redact_fields: frozenset[str] = field(default_factory=lambda: _DEFAULT_REDACT_FIELDS)
    redact_patterns: tuple[str, ...] = field(default_factory=lambda: _DEFAULT_REDACT_PATTERNS)
    max_value_length: int = 2048
    max_collection_items: int = 64
    max_depth: int = 8
    max_breadcrumbs: int = 100
    max_frames: int = 50
    fingerprint_frame_limit: int = 10
    filename_prefix: str = "failure"
    normalize_exception_messages: bool = True
    capture_arguments: bool = True
    capture_locals: bool = False
    capture_argv: bool = False
    capture_cwd: bool = True
    capture_threads: bool = False
    re_raise: bool = True
    include_package_hashes: bool = True
    write_pretty_json: bool = True
    max_archive_files: int = 256
    max_archive_file_size: int = 50 * 1024 * 1024
    max_archive_total_size: int = 200 * 1024 * 1024
    max_compression_ratio: int = 200
    max_manifest_size: int = 512 * 1024
    max_exception_depth: int = 20
    max_exception_children: int = 32
    max_operation_length: int = 256
    max_traceback_text_length: int = 100_000
    max_replay_payload_size: int = 1_000_000

    def __post_init__(self) -> None:
        self._normalize_output_directory()
        self._normalize_redaction_rules()
        self._validate()

    def _normalize_output_directory(self) -> None:
        value = self.output_directory
        if isinstance(value, str):
            object.__setattr__(self, "output_directory", Path(value))
        elif not isinstance(value, Path):
            raise ConfigurationError("output_directory must be a pathlib.Path or string")

    def _normalize_redaction_rules(self) -> None:
        raw_fields = self.redact_fields
        if raw_fields is None or isinstance(raw_fields, (str, bytes)):
            raise ConfigurationError("redact_fields must be a collection of strings")
        try:
            field_values = tuple(raw_fields)
        except TypeError as error:
            raise ConfigurationError("redact_fields must be a collection of strings") from error
        if not all(isinstance(item, str) and item.strip() for item in field_values):
            raise ConfigurationError("redact_fields must contain non-empty strings")
        object.__setattr__(
            self,
            "redact_fields",
            frozenset(_normalize_field_name(item) for item in field_values),
        )

        raw_patterns = self.redact_patterns
        if raw_patterns is None or isinstance(raw_patterns, (str, bytes)):
            raise ConfigurationError("redact_patterns must be a collection of strings")
        try:
            patterns = tuple(raw_patterns)
        except TypeError as error:
            raise ConfigurationError("redact_patterns must be a collection of strings") from error
        if not all(isinstance(item, str) for item in patterns):
            raise ConfigurationError("redact_patterns must contain strings")
        for pattern in patterns:
            try:
                re.compile(pattern)
            except re.error as error:
                raise ConfigurationError(
                    f"invalid redaction pattern {pattern!r}: {error}"
                ) from error
        object.__setattr__(self, "redact_patterns", patterns)

    def _validate(self) -> None:
        for name in _INTEGER_LIMITS:
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool):
                raise ConfigurationError(f"{name} must be an integer")

        for name in _BOOLEAN_FIELDS:
            if not isinstance(getattr(self, name), bool):
                raise ConfigurationError(f"{name} must be a boolean")

        minimums = {
            "max_value_length": 16,
            "max_collection_items": 1,
            "max_depth": 1,
            "max_breadcrumbs": 1,
            "max_frames": 1,
            "fingerprint_frame_limit": 1,
            "max_archive_files": 1,
            "max_archive_file_size": 1,
            "max_archive_total_size": 1,
            "max_compression_ratio": 1,
            "max_manifest_size": 1,
            "max_exception_depth": 1,
            "max_exception_children": 0,
            "max_operation_length": 8,
            "max_traceback_text_length": 100,
            "max_replay_payload_size": 100,
        }
        for name, minimum in minimums.items():
            if getattr(self, name) < minimum:
                raise ConfigurationError(f"{name} must be >= {minimum}")

        if self.max_archive_total_size < self.max_archive_file_size:
            raise ConfigurationError("max_archive_total_size must be >= max_archive_file_size")
        if self.max_manifest_size > self.max_archive_file_size:
            raise ConfigurationError("max_manifest_size must be <= max_archive_file_size")
        if not isinstance(self.filename_prefix, str):
            raise ConfigurationError("filename_prefix must be a string")
        if not self.filename_prefix.strip():
            raise ConfigurationError("filename_prefix cannot be empty")
        if not self.include_package_hashes:
            raise ConfigurationError("package hashes are mandatory")

    def with_overrides(self, **kwargs: Any) -> TraceSeedConfig:
        values = {item.name: getattr(self, item.name) for item in fields(self)}
        values.update(kwargs)
        return TraceSeedConfig(**values)

    def with_redact_fields(self, extra: Iterable[str]) -> TraceSeedConfig:
        if isinstance(extra, (str, bytes)):
            raise ConfigurationError("extra redaction fields must be a collection of strings")
        values = tuple(extra)
        if not all(isinstance(item, str) and item.strip() for item in values):
            raise ConfigurationError("extra redaction fields must contain non-empty strings")
        return self.with_overrides(redact_fields=self.redact_fields | frozenset(values))


def _normalize_field_name(value: str) -> str:
    return value.casefold().replace("-", "_").replace(" ", "_")


_current_config: TraceSeedConfig | None = None


def get_config() -> TraceSeedConfig:
    global _current_config
    if _current_config is None:
        _current_config = TraceSeedConfig()
    return _current_config


def configure(config: TraceSeedConfig | None = None, **overrides: Any) -> TraceSeedConfig:
    global _current_config
    if config is not None and not isinstance(config, TraceSeedConfig):
        raise TypeError(f"expected TraceSeedConfig, got {type(config).__name__}")
    result = config or TraceSeedConfig()
    if overrides:
        result = result.with_overrides(**overrides)
    _current_config = result
    return result


def reset_config() -> TraceSeedConfig:
    global _current_config
    _current_config = TraceSeedConfig()
    return _current_config
