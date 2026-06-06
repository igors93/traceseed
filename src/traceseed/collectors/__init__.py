"""Coletores de dados para enriquecimento de registros de falha."""

from __future__ import annotations

import linecache
import os
import platform
import sys
import threading
import traceback as _traceback
from typing import Any, Protocol

from ..config import TraceSeedConfig
from ..models import ExceptionInfo, FrameInfo, RuntimeInfo


class Collector(Protocol):
    name: str

    def collect(
        self,
        exception: BaseException,
        ctx: Any,
        config: TraceSeedConfig,
    ) -> dict[str, Any]: ...


class CollectorRegistry:
    def __init__(self, collectors: list[Collector] | None = None) -> None:
        self._collectors: list[Collector] = list(collectors or [])

    def register(self, collector: Collector) -> None:
        if any(c.name == collector.name for c in self._collectors):
            raise ValueError(f"coletor {collector.name!r} já registrado")
        self._collectors.append(collector)

    def unregister(self, name: str) -> None:
        self._collectors = [c for c in self._collectors if c.name != name]

    def run(
        self,
        exception: BaseException,
        ctx: Any,
        config: TraceSeedConfig,
    ) -> tuple[dict[str, Any], list[dict[str, str]]]:
        extensions: dict[str, Any] = {}
        errors: list[dict[str, str]] = []
        for collector in self._collectors:
            try:
                result = collector.collect(exception, ctx, config)
                if isinstance(result, dict):
                    extensions.update(result)
            except Exception as exc:
                errors.append({
                    "collector": collector.name,
                    "error": type(exc).__name__,
                    "message": str(exc),
                })
        return extensions, errors


def build_exception_info(exc: BaseException) -> ExceptionInfo:
    cause = build_exception_info(exc.__cause__) if exc.__cause__ else None
    ctx = (
        build_exception_info(exc.__context__)
        if exc.__context__ and not exc.__suppress_context__
        else None
    )
    children = tuple(
        build_exception_info(child)
        for child in getattr(exc, "exceptions", None) or []
    )
    notes = tuple(getattr(exc, "__notes__", None) or [])
    return ExceptionInfo(
        module=type(exc).__module__,
        type_name=type(exc).__qualname__,
        message=str(exc),
        representation=repr(exc),
        cause=cause,
        context=ctx,
        suppress_context=bool(exc.__suppress_context__),
        notes=notes,
        children=children,
    )


def build_frames(exc: BaseException, config: TraceSeedConfig, redactor: Any = None) -> tuple[FrameInfo, ...]:
    frames: list[FrameInfo] = []
    tb = exc.__traceback__
    while tb is not None:
        frame = tb.tb_frame
        lineno = tb.tb_lineno
        filename = frame.f_code.co_filename
        source = linecache.getline(filename, lineno).strip() or None

        if config.capture_locals and redactor is not None:
            raw = {k: v for k, v in frame.f_locals.items() if not k.startswith("__")}
            locals_data = redactor.redact(raw)
        else:
            locals_data = {}

        frames.append(FrameInfo(
            filename=filename,
            function=frame.f_code.co_name,
            line_number=lineno,
            module=frame.f_globals.get("__name__"),
            source_line=source,
            locals=locals_data,
        ))
        tb = tb.tb_next

    return tuple(frames[: config.max_frames])


def build_runtime_info() -> RuntimeInfo:
    return RuntimeInfo(
        python_version=sys.version,
        implementation=platform.python_implementation(),
        operating_system=platform.system(),
        platform=platform.platform(),
        architecture=platform.architecture()[0],
        executable=sys.executable,
        cwd=os.getcwd(),
        process_id=os.getpid(),
        thread_name=threading.current_thread().name,
        argv=tuple(sys.argv),
    )
