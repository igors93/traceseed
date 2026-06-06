"""Contexto e breadcrumbs baseados em contextvars (isolados por task asyncio)."""

from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager
from contextvars import ContextVar, Token
from datetime import UTC, datetime
from typing import Any

from .models import Breadcrumb

_ctx_var: ContextVar[dict[str, Any] | None] = ContextVar("traceseed_context", default=None)
_crumbs_var: ContextVar[tuple[Breadcrumb, ...]] = ContextVar("traceseed_breadcrumbs", default=())


@contextmanager
def context(**kwargs: Any) -> Generator[None, None, None]:
    token = _ctx_var.set({**(_ctx_var.get() or {}), **kwargs})
    try:
        yield
    finally:
        _ctx_var.reset(token)


def current_context() -> dict[str, Any]:
    return dict(_ctx_var.get() or {})


def set_context(key: str, value: Any) -> Token:
    if not key:
        raise ValueError("key não pode ser vazia")
    new = {**(_ctx_var.get() or {}), key: value}
    return _ctx_var.set(new)


def reset_context(token: Token) -> None:
    _ctx_var.reset(token)


def clear_context() -> None:
    _ctx_var.set({})
    _crumbs_var.set(())


def breadcrumb(category: str, message: str, **data: Any) -> Breadcrumb:
    if not category.strip():
        raise ValueError("category não pode ser vazia")
    if not message.strip():
        raise ValueError("message não pode ser vazia")
    from .config import get_config

    item = Breadcrumb(
        timestamp=datetime.now(UTC),
        category=category,
        message=message,
        data=data,
    )
    crumbs = (*_crumbs_var.get(), item)
    limit = get_config().max_breadcrumbs
    if len(crumbs) > limit:
        crumbs = crumbs[-limit:]
    _crumbs_var.set(crumbs)
    return item


def current_breadcrumbs() -> tuple[Breadcrumb, ...]:
    return _crumbs_var.get()
