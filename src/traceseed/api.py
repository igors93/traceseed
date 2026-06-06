"""API pública: decoradores, context managers, hooks globais e registro."""

from __future__ import annotations

import asyncio
import functools
import inspect
import sys
import threading
from contextlib import contextmanager
from inspect import BoundArguments
from typing import Any, Callable, Generator, TypeVar

from .collectors import CollectorRegistry
from .config import TraceSeedConfig, get_config
from .context import clear_context as _clear_context  # noqa: F401 (re-exported)
from .context import context as _context_cm  # noqa: F401 (re-exported)
from .context import (
    breadcrumb as _breadcrumb,
    current_breadcrumbs,
    current_context,
    reset_context,
    set_context,
)
from .engine import CaptureEngine
from .models import CallableInfo, CaptureContext, CaptureResult
from .serialization import SafeSerializer
from .storage.archive import ArchiveStorage

F = TypeVar("F", bound=Callable[..., Any])

_global_registry: CollectorRegistry = CollectorRegistry()
_global_codecs: dict[str, Any] = {}
_installed: bool = False
_old_excepthook: Any = None
_old_thread_excepthook: Any = None
_old_loop_handler: Any = None
_last_capture: CaptureResult | None = None

_SKIP_TYPES = (KeyboardInterrupt, SystemExit)


def _make_serializer(config: TraceSeedConfig) -> SafeSerializer:
    ser = SafeSerializer(config)
    for codec in _global_codecs.values():
        ser.register_codec(codec)
    return ser


def _default_storage(config: TraceSeedConfig, serializer: SafeSerializer) -> ArchiveStorage:
    return ArchiveStorage(config, serializer)


def _is_importable(func: Callable[..., Any]) -> bool:
    module = getattr(func, "__module__", None)
    qualname = getattr(func, "__qualname__", "")
    if module in (None, "__main__"):
        return False
    if "<locals>" in qualname:
        return False
    return True


def _bind_arguments(func: Callable[..., Any], args: tuple, kwargs: dict) -> dict[str, Any]:
    try:
        sig = inspect.signature(func)
        bound: BoundArguments = sig.bind(*args, **kwargs)
        bound.apply_defaults()
        return dict(bound.arguments)
    except (TypeError, ValueError):
        return {}


def capture_exception(
    exception: BaseException,
    *,
    config: TraceSeedConfig | None = None,
    storage: Any = None,
    metadata: dict[str, Any] | None = None,
    operation: str | None = None,
    callable_info: CallableInfo | None = None,
    replay_arguments: tuple | None = None,
    replay_keyword_arguments: dict | None = None,
    strict: bool = False,
    on_captured: Callable[[CaptureResult], Any] | None = None,
) -> CaptureResult | None:
    if not isinstance(exception, BaseException):
        raise TypeError(f"esperado BaseException, recebeu {type(exception).__name__}")

    cfg = config or get_config()
    ser = _make_serializer(cfg)
    stor = storage if storage is not None else _default_storage(cfg, ser)

    ctx = CaptureContext(
        operation=operation,
        metadata=metadata or {},
        arguments={},
        callable_info=callable_info,
        replay_arguments=replay_arguments,
        replay_keyword_arguments=replay_keyword_arguments,
    )

    engine = CaptureEngine(
        config=cfg,
        collectors=_global_registry,
        storage=stor,
        serializer=ser,
    )

    result = engine.capture(exception, ctx)

    if result.capture_error:
        if strict:
            from .errors import StorageError
            raise StorageError(result.capture_error)
        print(f"traceseed: {result.capture_error}", file=sys.stderr)
        return None

    global _last_capture
    _last_capture = result

    if on_captured is not None:
        try:
            on_captured(result)
        except Exception:
            pass

    return result


def _do_capture(
    func: Callable[..., Any],
    args: tuple,
    kwargs: dict,
    *,
    cfg: TraceSeedConfig,
    storage: Any,
    operation: str | None,
    replayable: bool,
    on_captured: Callable | None,
    strict: bool,
) -> CaptureResult | None:
    arguments = _bind_arguments(func, args, kwargs)
    callable_info: CallableInfo | None = None
    replay_args: tuple | None = None
    replay_kwargs: dict | None = None

    if replayable:
        importable = _is_importable(func)
        callable_info = CallableInfo(
            module=getattr(func, "__module__", ""),
            qualname=getattr(func, "__qualname__", ""),
            replayable=importable,
            reason=None if importable else "callable não importável",
        )
        if importable:
            replay_args = args
            replay_kwargs = kwargs
    else:
        callable_info = CallableInfo(
            module=getattr(func, "__module__", ""),
            qualname=getattr(func, "__qualname__", ""),
            replayable=False,
        )

    op = operation or getattr(func, "__qualname__", None)
    ser = _make_serializer(cfg)
    stor = storage if storage is not None else _default_storage(cfg, ser)

    ctx = CaptureContext(
        operation=op,
        metadata={},
        arguments=arguments,
        callable_info=callable_info,
        replay_arguments=replay_args,
        replay_keyword_arguments=replay_kwargs,
    )

    engine = CaptureEngine(
        config=cfg,
        collectors=_global_registry,
        storage=stor,
        serializer=ser,
    )

    try:
        result = engine.capture(func.__self__ if hasattr(func, "__self__") else func, ctx)  # type: ignore
        return result
    except Exception:
        pass

    return None


def capture(
    func: F | None = None,
    *,
    storage: Any = None,
    config: TraceSeedConfig | None = None,
    replayable: bool = False,
    operation: str | None = None,
    on_captured: Callable[[CaptureResult], Any] | None = None,
    strict: bool = False,
) -> Any:
    def decorator(fn: F) -> F:
        if asyncio.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                cfg = config or get_config()
                try:
                    return await fn(*args, **kwargs)
                except _SKIP_TYPES:
                    raise
                except BaseException as exc:
                    arguments = _bind_arguments(fn, args, kwargs)
                    importable = _is_importable(fn) and replayable
                    ci = CallableInfo(
                        module=getattr(fn, "__module__", ""),
                        qualname=getattr(fn, "__qualname__", ""),
                        replayable=importable,
                        reason=None if importable else ("callable não importável" if replayable else None),
                    )
                    op = operation or getattr(fn, "__qualname__", None)
                    ser = _make_serializer(cfg)
                    stor = storage if storage is not None else _default_storage(cfg, ser)
                    ctx = CaptureContext(
                        operation=op,
                        metadata={},
                        arguments=arguments,
                        callable_info=ci,
                        replay_arguments=args if importable else None,
                        replay_keyword_arguments=kwargs if importable else None,
                    )
                    engine = CaptureEngine(cfg, _global_registry, stor, ser)
                    result = _run_engine_safe(engine, exc, ctx, strict)
                    if result is not None:
                        global _last_capture
                        _last_capture = result
                        if on_captured:
                            try:
                                on_captured(result)
                            except Exception:
                                pass
                    if cfg.re_raise:
                        raise
                    return None
            return async_wrapper  # type: ignore
        else:
            @functools.wraps(fn)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                cfg = config or get_config()
                try:
                    return fn(*args, **kwargs)
                except _SKIP_TYPES:
                    raise
                except BaseException as exc:
                    arguments = _bind_arguments(fn, args, kwargs)
                    importable = _is_importable(fn) and replayable
                    ci = CallableInfo(
                        module=getattr(fn, "__module__", ""),
                        qualname=getattr(fn, "__qualname__", ""),
                        replayable=importable,
                        reason=None if importable else ("callable não importável" if replayable else None),
                    )
                    op = operation or getattr(fn, "__qualname__", None)
                    ser = _make_serializer(cfg)
                    stor = storage if storage is not None else _default_storage(cfg, ser)
                    ctx = CaptureContext(
                        operation=op,
                        metadata={},
                        arguments=arguments,
                        callable_info=ci,
                        replay_arguments=args if importable else None,
                        replay_keyword_arguments=kwargs if importable else None,
                    )
                    engine = CaptureEngine(cfg, _global_registry, stor, ser)
                    result = _run_engine_safe(engine, exc, ctx, strict)
                    if result is not None:
                        global _last_capture
                        _last_capture = result
                        if on_captured:
                            try:
                                on_captured(result)
                            except Exception:
                                pass
                    if cfg.re_raise:
                        raise
                    return None
            return sync_wrapper  # type: ignore

    if func is not None:
        return decorator(func)
    return decorator


def _run_engine_safe(
    engine: CaptureEngine,
    exc: BaseException,
    ctx: CaptureContext,
    strict: bool = False,
) -> CaptureResult | None:
    result = engine.capture(exc, ctx)
    if result.capture_error:
        print(f"traceseed: {result.capture_error}", file=sys.stderr)
        return None
    return result


@contextmanager
def guard(
    operation: str,
    *,
    storage: Any = None,
    config: TraceSeedConfig | None = None,
    on_captured: Callable[[CaptureResult], Any] | None = None,
    strict: bool = False,
) -> Generator[None, None, None]:
    cfg = config or get_config()
    try:
        yield
    except _SKIP_TYPES:
        raise
    except BaseException as exc:
        ser = _make_serializer(cfg)
        stor = storage if storage is not None else _default_storage(cfg, ser)
        ctx = CaptureContext(operation=operation, metadata={}, arguments={})
        engine = CaptureEngine(cfg, _global_registry, stor, ser)
        result = _run_engine_safe(engine, exc, ctx, strict)
        if result is not None:
            global _last_capture
            _last_capture = result
            if on_captured:
                try:
                    on_captured(result)
                except Exception:
                    pass
        if cfg.re_raise:
            raise


def get_last_capture() -> CaptureResult | None:
    return _last_capture


def register_collector(collector: Any) -> None:
    _global_registry.register(collector)


def unregister_collector(name: str) -> None:
    _global_registry.unregister(name)


def register_codec(codec: Any) -> None:
    _global_codecs[codec.type_name] = codec


def unregister_codec(name: str) -> None:
    _global_codecs.pop(name, None)


def install(storage: Any = None, config: TraceSeedConfig | None = None) -> None:
    global _installed, _old_excepthook, _old_thread_excepthook

    if _installed:
        return

    cfg = config
    stor = storage

    def _sys_excepthook(exc_type: type, exc_value: BaseException, exc_tb: Any) -> None:
        try:
            capture_exception(exc_value, config=cfg, storage=stor)
        except Exception:
            pass
        sys.__excepthook__(exc_type, exc_value, exc_tb)

    def _thread_excepthook(args: threading.ExceptHookArgs) -> None:
        if args.exc_value is not None:
            try:
                capture_exception(args.exc_value, config=cfg, storage=stor)
            except Exception:
                pass

    _old_excepthook = sys.excepthook
    _old_thread_excepthook = threading.excepthook

    sys.excepthook = _sys_excepthook
    threading.excepthook = _thread_excepthook
    _installed = True


def uninstall() -> None:
    global _installed, _old_excepthook, _old_thread_excepthook

    if not _installed:
        return

    if _old_excepthook is not None:
        sys.excepthook = _old_excepthook
    if _old_thread_excepthook is not None:
        threading.excepthook = _old_thread_excepthook

    _old_excepthook = None
    _old_thread_excepthook = None
    _installed = False
