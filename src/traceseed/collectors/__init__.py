"""Coletores de dados para enriquecimento de registros de falha."""

from __future__ import annotations

import linecache
import os
import platform
import sys
import threading
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
                try:
                    msg = str(exc)
                except Exception:
                    msg = type(exc).__name__
                errors.append(
                    {
                        "collector": collector.name,
                        "error": type(exc).__name__,
                        "message": msg,
                    }
                )
        return extensions, errors


def build_exception_info(
    exc: BaseException,
    _depth: int = 0,
    _seen: frozenset[int] | None = None,
    max_depth: int = 20,
    max_children: int = 32,
) -> ExceptionInfo:
    """Constrói ExceptionInfo com proteção a ciclos, profundidade e exceções defeituosas.

    Nunca causa recursão infinita nem lança exceção para o chamador.
    """
    if _seen is None:
        _seen = frozenset()
    if _depth > max_depth or id(exc) in _seen:
        try:
            module = type(exc).__module__
            type_name = type(exc).__qualname__
        except Exception:
            module = "unknown"
            type_name = "unknown"
        return ExceptionInfo(
            module=module,
            type_name=type_name,
            message="[DEPTH_OR_CYCLE_LIMIT]",
            representation="[DEPTH_OR_CYCLE_LIMIT]",
        )
    _seen = _seen | {id(exc)}

    try:
        message = str(exc)
    except Exception:
        message = "[str() raised]"

    try:
        representation = repr(exc)
    except Exception:
        representation = "[repr() raised]"

    try:
        module = type(exc).__module__
    except Exception:
        module = "unknown"

    try:
        type_name = type(exc).__qualname__
    except Exception:
        type_name = "unknown"

    cause: ExceptionInfo | None = None
    if exc.__cause__ is not None:
        cause = build_exception_info(exc.__cause__, _depth + 1, _seen, max_depth, max_children)

    ctx: ExceptionInfo | None = None
    if exc.__context__ is not None and not exc.__suppress_context__:
        ctx = build_exception_info(exc.__context__, _depth + 1, _seen, max_depth, max_children)

    raw_children = list(getattr(exc, "exceptions", None) or [])[:max_children]
    children = tuple(
        build_exception_info(child, _depth + 1, _seen, max_depth, max_children)
        for child in raw_children
    )

    notes: tuple[str, ...] = ()
    try:
        raw_notes = getattr(exc, "__notes__", None) or []
        notes = tuple(n if isinstance(n, str) else repr(n) for n in raw_notes)
    except Exception:
        notes = ("[notes failed]",)

    return ExceptionInfo(
        module=module,
        type_name=type_name,
        message=message,
        representation=representation,
        cause=cause,
        context=ctx,
        suppress_context=bool(exc.__suppress_context__),
        notes=notes,
        children=children,
    )


def build_frames(
    exc: BaseException, config: TraceSeedConfig, redactor: Any = None
) -> tuple[FrameInfo, ...]:
    frames: list[FrameInfo] = []
    tb = exc.__traceback__
    while tb is not None:
        frame = tb.tb_frame
        lineno = tb.tb_lineno
        filename = frame.f_code.co_filename
        source: str | None = linecache.getline(filename, lineno).strip() or None

        # Sanitiza source_line para evitar vazar segredos do código-fonte
        if source is not None and redactor is not None:
            source = redactor.redact_text(source)

        if config.capture_locals and redactor is not None:
            raw = {k: v for k, v in frame.f_locals.items() if not k.startswith("__")}
            locals_data = redactor.redact(raw)
        else:
            locals_data = {}

        frames.append(
            FrameInfo(
                filename=filename,
                function=frame.f_code.co_name,
                line_number=lineno,
                module=frame.f_globals.get("__name__"),
                source_line=source,
                locals=locals_data,
            )
        )
        tb = tb.tb_next

    return tuple(frames[: config.max_frames])


def build_runtime_info(config: TraceSeedConfig) -> RuntimeInfo:
    argv = tuple(sys.argv) if config.capture_argv else ()
    cwd = os.getcwd() if config.capture_cwd else ""
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
