"""Serializable domain models used by TraceSeed."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass(frozen=True, slots=True)
class ExceptionInfo:
    module: str
    type_name: str
    message: str
    representation: str
    cause: ExceptionInfo | None = None
    context: ExceptionInfo | None = None
    suppress_context: bool = False
    notes: tuple[str, ...] = ()
    children: tuple[ExceptionInfo, ...] = ()


@dataclass(frozen=True, slots=True)
class FrameInfo:
    filename: str
    function: str
    line_number: int
    module: str | None = None
    source_line: str | None = None
    locals: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class RuntimeInfo:
    python_version: str
    implementation: str
    operating_system: str
    platform: str
    architecture: str
    executable: str
    cwd: str
    process_id: int
    thread_name: str
    argv: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Breadcrumb:
    timestamp: datetime
    category: str
    message: str
    data: dict[str, Any] = field(default_factory=dict)
    level: str = "info"


@dataclass(frozen=True, slots=True)
class CallableInfo:
    module: str
    qualname: str
    replayable: bool
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class CaptureContext:
    operation: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    arguments: dict[str, Any] = field(default_factory=dict)
    callable_info: CallableInfo | None = None
    replay_arguments: tuple[Any, ...] | None = None
    replay_keyword_arguments: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class FailureRecord:
    incident_id: str
    fingerprint: str
    created_at: datetime
    operation: str | None
    exception: ExceptionInfo
    frames: tuple[FrameInfo, ...]
    runtime: RuntimeInfo | None
    arguments: dict[str, Any]
    metadata: dict[str, Any]
    breadcrumbs: tuple[Breadcrumb, ...]
    collector_errors: tuple[dict[str, str], ...] = ()
    extensions: dict[str, Any] = field(default_factory=dict)
    callable_info: CallableInfo | None = None
    format_version: int = 1
    library_version: str = "0.1.0"

    @staticmethod
    def utc_now() -> datetime:
        return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class CaptureResult:
    record: FailureRecord
    location: str | None
    storage_name: str
    capture_error: str | None = None
