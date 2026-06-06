"""TraceSeed exception hierarchy."""

from __future__ import annotations


class TraceSeedError(Exception):
    """Base class for TraceSeed errors."""


class ConfigurationError(TraceSeedError, ValueError):
    """Raised when configuration is invalid or inconsistent."""


class SerializationError(TraceSeedError, ValueError):
    """Raised when a value cannot be encoded or decoded safely."""


class StorageError(TraceSeedError, OSError):
    """Raised when a package cannot be persisted or loaded."""


class IntegrityError(StorageError):
    """Raised when a package hash does not match its manifest."""


class InvalidPackageError(StorageError):
    """Raised when a diagnostic package is malformed or unsupported."""


class ReplayError(TraceSeedError, RuntimeError):
    """Raised when replay inspection or execution is unsafe or invalid."""


class CallbackError(TraceSeedError):
    """Raised when an on_captured callback fails in strict mode."""
