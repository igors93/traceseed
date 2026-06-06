"""Storage em memória para testes e integrações."""

from __future__ import annotations

from typing import Any

from ..models import FailureRecord
from .base import StoredFailure


class MemoryStorage:
    name = "memory"

    def __init__(self) -> None:
        self.records: list[FailureRecord] = []
        self.extras: list[dict[str, Any]] = []

    def save(self, record: FailureRecord, extra: dict[str, Any] | None = None) -> StoredFailure:
        self.records.append(record)
        self.extras.append(dict(extra or {}))
        return StoredFailure(location=f"memory://{record.incident_id}", storage_name=self.name)

    def load_files(self, location: str) -> dict[str, bytes]:
        raise NotImplementedError("MemoryStorage armazena modelos, não arquivos")
