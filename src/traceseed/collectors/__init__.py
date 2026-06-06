"""Failure data collectors and collector isolation."""

from __future__ import annotations

import linecache
import os
import platform
import sys
import threading
from collections import Counter
from typing import Any, Protocol

from ..config import TraceSeedConfig
from ..models import ExceptionInfo, FrameInfo, RuntimeInfo


class Collector(Protocol):
    name: str

    def collect(
        self,
        exception: BaseException,
        context: Any,
        config: TraceSeedConfig,
    ) -> dict[str, Any]: ...


def _safe_collector_name(collector: Any) -> tuple[str, str | None]:
    try:
        name = collector.name
    except Exception as error:
        fallback = f"collector:{type(collector).__module__}.{type(collector).__qualname__}"
        return fallback, f"collector name failed: {type(error).__name__}"
    if not isinstance(name, str) or not name.strip():
        fallback = f"collector:{type(collector).__module__}.{type(collector).__qualname__}"
        return fallback, "collector name must be a non-empty string"
    return name, None


class CollectorRegistry:
    def __init__(self, collectors: list[Collector] | None = None) -> None:
        self._collectors: list[Collector] = list(collectors or [])

    def register(self, collector: Collector) -> None:
        name, name_error = _safe_collector_name(collector)
        if name_error is not None:
            raise ValueError(name_error)
        for current in self._collectors:
            current_name, _ = _safe_collector_name(current)
            if current_name == name:
                raise ValueError(f"collector {name!r} is already registered")
        self._collectors.append(collector)

    def unregister(self, name: str) -> None:
        retained: list[Collector] = []
        for collector in self._collectors:
            current_name, _ = _safe_collector_name(collector)
            if current_name != name:
                retained.append(collector)
        self._collectors = retained

    def snapshot(self) -> tuple[Collector, ...]:
        return tuple(self._collectors)

    def run(
        self,
        exception: BaseException,
        context: Any,
        config: TraceSeedConfig,
    ) -> tuple[dict[str, Any], list[dict[str, str]]]:
        successful: list[tuple[str, dict[str, Any]]] = []
        errors: list[dict[str, str]] = []

        for collector in self.snapshot():
            name, name_error = _safe_collector_name(collector)
            if name_error is not None:
                errors.append(
                    {
                        "collector": name,
                        "error": "InvalidCollectorName",
                        "message": name_error,
                    }
                )
            try:
                result = collector.collect(exception, context, config)
            except Exception as error:
                errors.append(
                    {
                        "collector": name,
                        "error": type(error).__name__,
                        "message": _safe_exception_text(error),
                    }
                )
                continue
            if not isinstance(result, dict):
                errors.append(
                    {
                        "collector": name,
                        "error": "InvalidCollectorResult",
                        "message": "collector result must be a dictionary",
                    }
                )
                continue
            if not all(isinstance(key, str) for key in result):
                errors.append(
                    {
                        "collector": name,
                        "error": "InvalidCollectorResult",
                        "message": "collector result keys must be strings",
                    }
                )
                continue
            successful.append((name, result))

        key_counts = Counter(key for _, result in successful for key in result)
        extensions: dict[str, Any] = {}
        for name, result in successful:
            if any(key_counts[key] > 1 for key in result):
                safe_name = name
                suffix = 2
                while safe_name in extensions:
                    safe_name = f"{name}-{suffix}"
                    suffix += 1
                extensions[safe_name] = dict(result)
            else:
                extensions.update(result)
        return extensions, errors


def _safe_exception_text(error: BaseException) -> str:
    try:
        return str(error)
    except Exception:
        return type(error).__name__


def build_exception_info(
    exception: BaseException,
    _depth: int = 0,
    _seen: frozenset[int] | None = None,
    max_depth: int = 20,
    max_children: int = 32,
) -> ExceptionInfo:
    """Build exception information without unbounded recursion or unsafe repr calls."""
    seen = _seen or frozenset()
    if _depth >= max_depth or id(exception) in seen:
        return ExceptionInfo(
            module=_safe_type_attribute(exception, "__module__"),
            type_name=_safe_type_attribute(exception, "__qualname__"),
            message="[DEPTH_OR_CYCLE_LIMIT]",
            representation="[DEPTH_OR_CYCLE_LIMIT]",
        )
    seen = seen | {id(exception)}

    message = _safe_call(str, exception, "[str() raised]")
    representation = _safe_call(repr, exception, "[repr() raised]")
    module = _safe_type_attribute(exception, "__module__")
    type_name = _safe_type_attribute(exception, "__qualname__")

    cause = None
    try:
        raw_cause = exception.__cause__
    except Exception:
        raw_cause = None
    if raw_cause is not None:
        cause = build_exception_info(raw_cause, _depth + 1, seen, max_depth, max_children)

    context = None
    try:
        raw_context = exception.__context__
        suppress_context = bool(exception.__suppress_context__)
    except Exception:
        raw_context = None
        suppress_context = False
    if raw_context is not None and not suppress_context:
        context = build_exception_info(raw_context, _depth + 1, seen, max_depth, max_children)

    try:
        raw_children = getattr(exception, "exceptions", None) or ()
        children_values = list(raw_children)[:max_children]
    except Exception:
        children_values = []
    children = tuple(
        build_exception_info(child, _depth + 1, seen, max_depth, max_children)
        for child in children_values
        if isinstance(child, BaseException)
    )

    try:
        raw_notes = getattr(exception, "__notes__", None) or ()
        notes = tuple(
            note if isinstance(note, str) else _safe_call(repr, note, "[note repr failed]")
            for note in list(raw_notes)[:max_children]
        )
    except Exception:
        notes = ("[notes failed]",)

    return ExceptionInfo(
        module=module,
        type_name=type_name,
        message=message,
        representation=representation,
        cause=cause,
        context=context,
        suppress_context=suppress_context,
        notes=notes,
        children=children,
    )


def _safe_call(function: Any, value: Any, fallback: str) -> str:
    try:
        result = function(value)
        return result if isinstance(result, str) else fallback
    except Exception:
        return fallback


def _safe_type_attribute(value: Any, name: str) -> str:
    try:
        result = getattr(type(value), name)
        return result if isinstance(result, str) else "unknown"
    except Exception:
        return "unknown"


def build_frames(
    exception: BaseException,
    config: TraceSeedConfig,
    redactor: Any = None,
) -> tuple[FrameInfo, ...]:
    frames: list[FrameInfo] = []
    try:
        traceback = exception.__traceback__
    except Exception:
        traceback = None
    while traceback is not None and len(frames) < config.max_frames:
        frame = traceback.tb_frame
        line_number = traceback.tb_lineno
        filename = frame.f_code.co_filename
        source = linecache.getline(filename, line_number).strip() or None
        if redactor is not None:
            filename = redactor.redact_text(filename)
            source = redactor.redact_text(source) if source is not None else None
            module_value = frame.f_globals.get("__name__")
            module = redactor.redact_text(str(module_value)) if module_value is not None else None
        else:
            module_value = frame.f_globals.get("__name__")
            module = str(module_value) if module_value is not None else None

        if config.capture_locals and redactor is not None:
            try:
                raw_locals = {
                    key: value
                    for key, value in frame.f_locals.items()
                    if isinstance(key, str) and not key.startswith("__")
                }
                locals_data = redactor.redact(raw_locals)
            except Exception:
                locals_data = {"capture_error": "unable to read frame locals"}
        else:
            locals_data = {}

        frames.append(
            FrameInfo(
                filename=filename,
                function=redactor.redact_text(frame.f_code.co_name)
                if redactor is not None
                else frame.f_code.co_name,
                line_number=line_number,
                module=module,
                source_line=source,
                locals=locals_data,
            )
        )
        traceback = traceback.tb_next
    return tuple(frames)


def build_runtime_info(config: TraceSeedConfig) -> RuntimeInfo:
    argv = tuple(str(item) for item in sys.argv) if config.capture_argv else ()
    try:
        cwd = os.getcwd() if config.capture_cwd else ""
    except OSError:
        cwd = ""
    return RuntimeInfo(
        python_version=sys.version,
        implementation=platform.python_implementation(),
        operating_system=platform.system(),
        platform=platform.platform(),
        architecture=platform.architecture()[0],
        executable=sys.executable,
        cwd=cwd,
        process_id=os.getpid(),
        thread_name=threading.current_thread().name,
        argv=argv,
    )


def build_thread_info(config: TraceSeedConfig) -> tuple[dict[str, Any], ...]:
    if not config.capture_threads:
        return ()
    result = []
    for thread in list(threading.enumerate())[: config.max_collection_items]:
        result.append(
            {
                "name": thread.name,
                "identifier": thread.ident,
                "daemon": thread.daemon,
                "alive": thread.is_alive(),
            }
        )
    return tuple(result)
