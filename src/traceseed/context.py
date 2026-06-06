"""Task-local context and breadcrumbs based on contextvars."""

from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager
from contextvars import ContextVar, Token
from datetime import UTC, datetime
from typing import Any

from .models import Breadcrumb

_context_var: ContextVar[dict[str, Any] | None] = ContextVar("traceseed_context", default=None)
_breadcrumbs_var: ContextVar[tuple[Breadcrumb, ...]] = ContextVar(
    "traceseed_breadcrumbs", default=()
)


@contextmanager
def context(**kwargs: Any) -> Generator[None, None, None]:
    token = _context_var.set({**(_context_var.get() or {}), **kwargs})
    try:
        yield
    finally:
        _context_var.reset(token)


def current_context() -> dict[str, Any]:
    return dict(_context_var.get() or {})


def set_context(key: str, value: Any) -> Token:
    if not isinstance(key, str) or not key:
        raise ValueError("key cannot be empty")
    return _context_var.set({**(_context_var.get() or {}), key: value})


def reset_context(token: Token) -> None:
    _context_var.reset(token)


def clear_context() -> None:
    _context_var.set({})
    _breadcrumbs_var.set(())


def breadcrumb(category: str, message: str, **data: Any) -> Breadcrumb:
    if not isinstance(category, str) or not category.strip():
        raise ValueError("category cannot be empty")
    if not isinstance(message, str) or not message.strip():
        raise ValueError("message cannot be empty")
    from .config import get_config

    item = Breadcrumb(
        timestamp=datetime.now(UTC),
        category=category,
        message=message,
        data=data,
    )
    values = (*_breadcrumbs_var.get(), item)
    limit = get_config().max_breadcrumbs
    if len(values) > limit:
        values = values[-limit:]
    _breadcrumbs_var.set(values)
    return item


def current_breadcrumbs() -> tuple[Breadcrumb, ...]:
    return _breadcrumbs_var.get()
