"""API pública: decoradores, context managers, hooks globais e registro.

Semântica de strict:
  strict=False (padrão): falhas internas de captura não substituem a exceção
    original; o erro vai para stderr; re_raise continua funcionando normalmente.
  strict=True: falhas internas levantam StorageError (com exceção original como
    __cause__); falha de callback levanta CallbackError; o comportamento é igual
    nos quatro contextos de captura.

asyncio hooks:
  install_asyncio() é idempotente por loop: instalar duas vezes não empilha
  wrappers. Usa WeakKeyDictionary para evitar retenção de loops e colisão
  de id() após garbage collection.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import sys
import threading
import weakref
from collections.abc import Callable, Generator
from contextlib import contextmanager, suppress
from inspect import BoundArguments
from typing import Any, TypeVar

from .collectors import CollectorRegistry
from .config import TraceSeedConfig, get_config
from .engine import CaptureEngine
from .errors import CallbackError, StorageError
from .models import CallableInfo, CaptureContext, CaptureResult
from .serialization import SafeSerializer
from .storage.archive import ArchiveStorage

F = TypeVar("F", bound=Callable[..., Any])

_global_registry: CollectorRegistry = CollectorRegistry()
_global_codecs: dict[str, Any] = {}
_installed: bool = False
_old_excepthook: Any = None
_old_thread_excepthook: Any = None
_last_capture: CaptureResult | None = None

# Asyncio: WeakKeyDictionary usa a referência real do loop como chave.
# Quando o loop é coletado pelo GC, a entrada some automaticamente.
# Isso evita colisões de id() entre loops destruídos e novos.
_asyncio_handlers: weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, Any] = (
    weakref.WeakKeyDictionary()
)

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
    return "<locals>" not in qualname


def _bind_arguments(func: Callable[..., Any], args: tuple, kwargs: dict) -> dict[str, Any]:
    try:
        sig = inspect.signature(func)
        bound: BoundArguments = sig.bind(*args, **kwargs)
        bound.apply_defaults()
        return dict(bound.arguments)
    except (TypeError, ValueError):
        return {}


def _raise_strict(storage_error_msg: str, original: BaseException) -> None:
    """Levanta StorageError preservando a exceção original como __cause__."""
    raise StorageError(storage_error_msg) from original


def _invoke_callback(
    on_captured: Callable[[CaptureResult], Any],
    result: CaptureResult,
    strict: bool,
    original: BaseException,
) -> None:
    """Invoca on_captured respeitando strict."""
    if strict:
        try:
            on_captured(result)
        except Exception as cb_err:
            raise CallbackError(str(cb_err)) from original
    else:
        with suppress(Exception):
            on_captured(result)


# ---------------------------------------------------------------------------
# capture_exception
# ---------------------------------------------------------------------------


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
            raise StorageError(result.capture_error) from exception
        print(f"traceseed: {result.capture_error}", file=sys.stderr)
        return None

    global _last_capture
    _last_capture = result

    if on_captured is not None:
        _invoke_callback(on_captured, result, strict, exception)

    return result


# ---------------------------------------------------------------------------
# Decorator @capture
# ---------------------------------------------------------------------------


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
                    _capture_in_wrapper(
                        fn,
                        args,
                        kwargs,
                        exc,
                        cfg,
                        replayable,
                        operation,
                        storage,
                        on_captured,
                        strict,
                    )
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
                    _capture_in_wrapper(
                        fn,
                        args,
                        kwargs,
                        exc,
                        cfg,
                        replayable,
                        operation,
                        storage,
                        on_captured,
                        strict,
                    )
                    if cfg.re_raise:
                        raise
                    return None

            return sync_wrapper  # type: ignore

    if func is not None:
        return decorator(func)
    return decorator


def _capture_in_wrapper(
    fn: Callable[..., Any],
    args: tuple,
    kwargs: dict,
    exc: BaseException,
    cfg: TraceSeedConfig,
    replayable: bool,
    operation: str | None,
    storage: Any,
    on_captured: Callable | None,
    strict: bool,
) -> None:
    """Lógica comum de captura para decoradores sync e async."""
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
    result = engine.capture(exc, ctx)

    if result.capture_error:
        if strict:
            raise StorageError(result.capture_error) from exc
        print(f"traceseed: {result.capture_error}", file=sys.stderr)
        return

    global _last_capture
    _last_capture = result
    if on_captured:
        _invoke_callback(on_captured, result, strict, exc)


# ---------------------------------------------------------------------------
# guard context manager
# ---------------------------------------------------------------------------


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
        result = engine.capture(exc, ctx)

        if result.capture_error:
            if strict:
                raise StorageError(result.capture_error) from exc
            print(f"traceseed: {result.capture_error}", file=sys.stderr)
        else:
            global _last_capture
            _last_capture = result
            if on_captured:
                _invoke_callback(on_captured, result, strict, exc)

        if cfg.re_raise:
            raise


# ---------------------------------------------------------------------------
# Hooks globais
# ---------------------------------------------------------------------------


def install(storage: Any = None, config: TraceSeedConfig | None = None) -> None:
    """Instala hooks em sys.excepthook e threading.excepthook.

    É idempotente: chamadas repetidas não instalam hooks duplos.
    O hook anterior (incluindo handlers customizados) é sempre chamado.
    """
    global _installed, _old_excepthook, _old_thread_excepthook

    if _installed:
        return

    cfg = config
    stor = storage
    # Captura os handlers atuais antes de sobrescrever
    prev_sys = sys.excepthook
    prev_thread = threading.excepthook

    def _sys_excepthook(exc_type: type, exc_value: BaseException, exc_tb: Any) -> None:
        with suppress(Exception):
            capture_exception(exc_value, config=cfg, storage=stor)
        # Chama o handler que estava instalado antes do TraceSeed
        try:
            prev_sys(exc_type, exc_value, exc_tb)
        except Exception:
            sys.__excepthook__(exc_type, exc_value, exc_tb)

    def _thread_excepthook(hook_args: threading.ExceptHookArgs) -> None:
        if hook_args.exc_value is not None:
            with suppress(Exception):
                capture_exception(hook_args.exc_value, config=cfg, storage=stor)
        # Chama o handler anterior
        with suppress(Exception):
            prev_thread(hook_args)

    _old_excepthook = prev_sys
    _old_thread_excepthook = prev_thread
    sys.excepthook = _sys_excepthook
    threading.excepthook = _thread_excepthook
    _installed = True


def uninstall() -> None:
    """Restaura exatamente os hooks que estavam instalados antes de install()."""
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
    """Instala handler de exceções no loop asyncio, preservando o handler anterior.

    É idempotente por loop: instalar duas vezes não empilha wrappers.
    Usa WeakKeyDictionary para evitar retenção do loop e colisão de id().

    Retorna o loop configurado (útil para chamar uninstall_asyncio depois).
    """
    cfg = config
    stor = storage

    try:
        lp = loop or asyncio.get_event_loop()
    except RuntimeError:
        lp = asyncio.new_event_loop()

    # Idempotência: se já instalado neste loop, retorna sem re-instalar
    if lp in _asyncio_handlers:
        return lp

    old_handler = lp.get_exception_handler()
    _asyncio_handlers[lp] = old_handler

    def _asyncio_handler(lp2: asyncio.AbstractEventLoop, context: dict[str, Any]) -> None:
        exc = context.get("exception")
        if exc is not None:
            with suppress(Exception):
                capture_exception(exc, config=cfg, storage=stor)
        if old_handler is not None:
            try:
                old_handler(lp2, context)
            except Exception:
                lp2.default_exception_handler(context)
        else:
            lp2.default_exception_handler(context)

    lp.set_exception_handler(_asyncio_handler)
    return lp


def uninstall_asyncio(loop: asyncio.AbstractEventLoop | None = None) -> None:
    """Restaura o handler asyncio anterior ao install_asyncio().

    É seguro chamar mais de uma vez (idempotente).
    """
    try:
        lp = loop or asyncio.get_event_loop()
    except RuntimeError:
        return

    if lp not in _asyncio_handlers:
        return

    lp.set_exception_handler(_asyncio_handlers.pop(lp))


# ---------------------------------------------------------------------------
# Registro global
# ---------------------------------------------------------------------------


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
