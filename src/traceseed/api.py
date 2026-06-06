"""Public capture API, hooks, and extension registration."""

from __future__ import annotations

import asyncio
import functools
import inspect
import sys
import threading
import weakref
from collections.abc import Callable, Generator
from contextlib import contextmanager, suppress
from contextvars import ContextVar
from inspect import BoundArguments
from typing import Any, TypeVar

from .collectors import CollectorRegistry
from .config import TraceSeedConfig, get_config
from .engine import CaptureEngine
from .errors import CallbackError, StorageError
from .models import CallableInfo, CaptureContext, CaptureResult
from .serialization import SafeSerializer, ValueCodec
from .storage.archive import ArchiveStorage

F = TypeVar("F", bound=Callable[..., Any])

_global_registry = CollectorRegistry()
_global_codecs: dict[str, ValueCodec] = {}
_registry_lock = threading.RLock()
_last_capture_var: ContextVar[CaptureResult | None] = ContextVar(
    "traceseed_last_capture",
    default=None,
)
_installed = False
_old_excepthook: Any = None
_old_thread_excepthook: Any = None
_asyncio_handlers: weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, Any] = (
    weakref.WeakKeyDictionary()
)


def _make_serializer(config: TraceSeedConfig) -> SafeSerializer:
    serializer = SafeSerializer(config)
    with _registry_lock:
        codecs = tuple(_global_codecs.values())
    for codec in codecs:
        serializer.register_codec(codec)
    return serializer


def _default_storage(
    config: TraceSeedConfig,
    serializer: SafeSerializer,
) -> ArchiveStorage:
    return ArchiveStorage(config, serializer)


def _is_importable(function: Callable[..., Any]) -> bool:
    module = getattr(function, "__module__", None)
    qualname = getattr(function, "__qualname__", "")
    return (
        isinstance(module, str)
        and module not in {"", "__main__"}
        and isinstance(qualname, str)
        and "<locals>" not in qualname
    )


def _bind_arguments(
    function: Callable[..., Any],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
) -> dict[str, Any]:
    try:
        signature = inspect.signature(function)
        bound: BoundArguments = signature.bind(*args, **kwargs)
        bound.apply_defaults()
        return dict(bound.arguments)
    except (TypeError, ValueError):
        return {}


def _invoke_callback(
    callback: Callable[[CaptureResult], Any],
    result: CaptureResult,
    strict: bool,
    original: BaseException,
) -> None:
    if strict:
        try:
            callback(result)
        except Exception as error:
            raise CallbackError(str(error)) from original
    else:
        with suppress(Exception):
            callback(result)


def _build_engine(
    config: TraceSeedConfig,
    storage: Any,
) -> CaptureEngine:
    serializer = _make_serializer(config)
    selected_storage = storage if storage is not None else _default_storage(config, serializer)
    return CaptureEngine(
        config=config,
        collectors=_global_registry,
        storage=selected_storage,
        serializer=serializer,
    )


def _handle_capture_result(
    result: CaptureResult,
    *,
    strict: bool,
    original: BaseException,
    callback: Callable[[CaptureResult], Any] | None,
) -> CaptureResult | None:
    if result.capture_error:
        if strict:
            raise StorageError(result.capture_error) from original
        print(f"traceseed: {result.capture_error}", file=sys.stderr)
        return None
    _last_capture_var.set(result)
    if callback is not None:
        _invoke_callback(callback, result, strict, original)
    return result


def capture_exception(
    exception: BaseException,
    *,
    config: TraceSeedConfig | None = None,
    storage: Any = None,
    metadata: dict[str, Any] | None = None,
    operation: str | None = None,
    callable_info: CallableInfo | None = None,
    replay_arguments: tuple[Any, ...] | None = None,
    replay_keyword_arguments: dict[str, Any] | None = None,
    strict: bool = False,
    on_captured: Callable[[CaptureResult], Any] | None = None,
) -> CaptureResult | None:
    if not isinstance(exception, BaseException):
        raise TypeError(f"expected BaseException, got {type(exception).__name__}")
    selected_config = config or get_config()
    try:
        engine = _build_engine(selected_config, storage)
        context = CaptureContext(
            operation=operation,
            metadata=dict(metadata or {}),
            arguments={},
            callable_info=callable_info,
            replay_arguments=replay_arguments,
            replay_keyword_arguments=replay_keyword_arguments,
        )
        result = engine.capture(exception, context)
    except Exception as error:
        if strict:
            raise StorageError(
                f"traceseed setup failed: {type(error).__name__}: {error}"
            ) from exception
        print(
            f"traceseed: setup failed: {type(error).__name__}: {error}",
            file=sys.stderr,
        )
        return None
    return _handle_capture_result(
        result,
        strict=strict,
        original=exception,
        callback=on_captured,
    )


def capture(
    function: F | None = None,
    *,
    storage: Any = None,
    config: TraceSeedConfig | None = None,
    replayable: bool = False,
    operation: str | None = None,
    metadata: dict[str, Any] | None = None,
    on_captured: Callable[[CaptureResult], Any] | None = None,
    strict: bool = False,
) -> Any:
    def decorator(wrapped: F) -> F:
        if inspect.iscoroutinefunction(wrapped):

            @functools.wraps(wrapped)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                selected_config = config or get_config()
                try:
                    return await wrapped(*args, **kwargs)
                except Exception as error:
                    _capture_in_wrapper(
                        wrapped,
                        args,
                        kwargs,
                        error,
                        selected_config,
                        replayable,
                        operation,
                        metadata,
                        storage,
                        on_captured,
                        strict,
                    )
                    if selected_config.re_raise:
                        raise
                    return None

            return async_wrapper  # type: ignore[return-value]

        @functools.wraps(wrapped)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            selected_config = config or get_config()
            try:
                return wrapped(*args, **kwargs)
            except Exception as error:
                _capture_in_wrapper(
                    wrapped,
                    args,
                    kwargs,
                    error,
                    selected_config,
                    replayable,
                    operation,
                    metadata,
                    storage,
                    on_captured,
                    strict,
                )
                if selected_config.re_raise:
                    raise
                return None

        return sync_wrapper  # type: ignore[return-value]

    if function is not None:
        return decorator(function)
    return decorator


def _capture_in_wrapper(
    function: Callable[..., Any],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    exception: Exception,
    config: TraceSeedConfig,
    replayable: bool,
    operation: str | None,
    metadata: dict[str, Any] | None,
    storage: Any,
    callback: Callable[[CaptureResult], Any] | None,
    strict: bool,
) -> None:
    importable = _is_importable(function) and replayable
    callable_info = CallableInfo(
        module=str(getattr(function, "__module__", "")),
        qualname=str(getattr(function, "__qualname__", "")),
        replayable=importable,
        reason=None if importable else ("callable is not importable" if replayable else None),
    )
    try:
        engine = _build_engine(config, storage)
        context = CaptureContext(
            operation=operation or getattr(function, "__qualname__", None),
            metadata=dict(metadata or {}),
            arguments=_bind_arguments(function, args, kwargs) if config.capture_arguments else {},
            callable_info=callable_info,
            replay_arguments=args if importable else None,
            replay_keyword_arguments=kwargs if importable else None,
        )
        result = engine.capture(exception, context)
    except Exception as error:
        if strict:
            raise StorageError(
                f"traceseed setup failed: {type(error).__name__}: {error}"
            ) from exception
        print(
            f"traceseed: setup failed: {type(error).__name__}: {error}",
            file=sys.stderr,
        )
        return
    _handle_capture_result(
        result,
        strict=strict,
        original=exception,
        callback=callback,
    )


@contextmanager
def guard(
    operation: str,
    *,
    storage: Any = None,
    config: TraceSeedConfig | None = None,
    metadata: dict[str, Any] | None = None,
    on_captured: Callable[[CaptureResult], Any] | None = None,
    strict: bool = False,
) -> Generator[None, None, None]:
    selected_config = config or get_config()
    try:
        yield
    except Exception as error:
        result = capture_exception(
            error,
            config=selected_config,
            storage=storage,
            metadata=metadata,
            operation=operation,
            strict=strict,
            on_captured=on_captured,
        )
        del result
        if selected_config.re_raise:
            raise


def install(storage: Any = None, config: TraceSeedConfig | None = None) -> None:
    global _installed, _old_excepthook, _old_thread_excepthook
    if _installed:
        return
    previous_sys = sys.excepthook
    previous_thread = threading.excepthook

    def system_hook(
        exception_type: type[BaseException],
        exception: BaseException,
        traceback: Any,
    ) -> None:
        if isinstance(exception, Exception):
            with suppress(Exception):
                capture_exception(exception, config=config, storage=storage)
        try:
            previous_sys(exception_type, exception, traceback)
        except Exception:
            sys.__excepthook__(exception_type, exception, traceback)

    def thread_hook(arguments: threading.ExceptHookArgs) -> None:
        if isinstance(arguments.exc_value, Exception):
            with suppress(Exception):
                capture_exception(arguments.exc_value, config=config, storage=storage)
        with suppress(Exception):
            previous_thread(arguments)

    _old_excepthook = previous_sys
    _old_thread_excepthook = previous_thread
    sys.excepthook = system_hook
    threading.excepthook = thread_hook
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


def install_asyncio(
    loop: asyncio.AbstractEventLoop | None = None,
    storage: Any = None,
    config: TraceSeedConfig | None = None,
) -> asyncio.AbstractEventLoop:
    try:
        selected_loop = loop or asyncio.get_event_loop()
    except RuntimeError:
        selected_loop = asyncio.new_event_loop()
    if selected_loop in _asyncio_handlers:
        return selected_loop
    previous = selected_loop.get_exception_handler()
    _asyncio_handlers[selected_loop] = previous

    def handler(
        current_loop: asyncio.AbstractEventLoop,
        context: dict[str, Any],
    ) -> None:
        exception = context.get("exception")
        if isinstance(exception, Exception):
            with suppress(Exception):
                capture_exception(exception, config=config, storage=storage)
        if previous is not None:
            try:
                previous(current_loop, context)
            except Exception:
                current_loop.default_exception_handler(context)
        else:
            current_loop.default_exception_handler(context)

    selected_loop.set_exception_handler(handler)
    return selected_loop


def uninstall_asyncio(loop: asyncio.AbstractEventLoop | None = None) -> None:
    try:
        selected_loop = loop or asyncio.get_event_loop()
    except RuntimeError:
        return
    if selected_loop in _asyncio_handlers:
        selected_loop.set_exception_handler(_asyncio_handlers.pop(selected_loop))


def get_last_capture() -> CaptureResult | None:
    return _last_capture_var.get()


def register_collector(collector: Any) -> None:
    with _registry_lock:
        _global_registry.register(collector)


def unregister_collector(name: str) -> None:
    with _registry_lock:
        _global_registry.unregister(name)


def register_codec(codec: ValueCodec) -> None:
    type_name = getattr(codec, "type_name", None)
    if not isinstance(type_name, str) or not type_name.strip():
        raise ValueError("codec must declare a non-empty type_name")
    with _registry_lock:
        if type_name in _global_codecs:
            raise ValueError(f"codec type_name {type_name!r} is already registered")
        _global_codecs[type_name] = codec


def unregister_codec(name: str) -> None:
    with _registry_lock:
        _global_codecs.pop(name, None)
