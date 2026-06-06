"""Logging integration that records log messages as breadcrumbs."""

from __future__ import annotations

import logging

from .context import breadcrumb


class BreadcrumbHandler(logging.Handler):
    """Convert log records into TraceSeed breadcrumbs."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            message = self.format(record)
            breadcrumb(
                record.name or "logging",
                message,
                level=record.levelname.casefold(),
                logger=record.name,
            )
        except Exception:
            self.handleError(record)
