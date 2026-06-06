"""Contratos e modelos de armazenamento."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from ..models import FailureRecord


@dataclass(frozen=True, slots=True)
class StoredFailure:
    location: str
    storage_name: str


class Storage(Protocol):
    name: str

    def save(self, record: FailureRecord, extra: dict[str, Any] | None = None) -> StoredFailure: ...
    def load_files(self, location: str | Path) -> dict[str, bytes]: ...
