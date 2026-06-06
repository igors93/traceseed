"""Integração opcional com logging como breadcrumbs."""

from __future__ import annotations

import logging

from .context import breadcrumb


class BreadcrumbHandler(logging.Handler):
    """Converte registros de logging em breadcrumbs do contexto atual."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            breadcrumb(
                "logging",
                record.getMessage(),
                level=record.levelname.casefold(),
                logger=record.name,
                pathname=record.pathname,
                line=record.lineno,
            )
        except Exception:
            self.handleError(record)
