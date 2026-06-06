"""Storage legível em diretórios, útil durante desenvolvimento."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any

from ..config import TraceSeedConfig
from ..errors import InvalidPackageError, StorageError
from ..models import FailureRecord
from ..serialization import SafeSerializer
from .archive import ArchiveStorage
from .base import StoredFailure

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


class DirectoryStorage:
    name = "directory"

    def __init__(self, config: TraceSeedConfig, serializer: SafeSerializer) -> None:
        self.config = config
        self.serializer = serializer
        self._archive_helper = ArchiveStorage(config, serializer)

    def save(self, record: FailureRecord, extra: dict[str, Any] | None = None) -> StoredFailure:
        root = self.config.output_directory
        root.mkdir(parents=True, exist_ok=True)
        operation = _SAFE_NAME.sub("-", record.operation or "failure").strip("-._") or "failure"
        target = root / f"{operation}-{record.fingerprint}-{record.incident_id.split('-')[0]}"
        temporary = Path(tempfile.mkdtemp(prefix=".traceseed-", dir=root))
        try:
            files = self._archive_helper._build_files(record, extra or {})
            hashes = {name: hashlib.sha256(content).hexdigest() for name, content in files.items()}
            manifest = {
                "format": "traceseed",
                "format_version": record.format_version,
                "library_version": record.library_version,
                "incident_id": record.incident_id,
                "fingerprint": record.fingerprint,
                "created_at": record.created_at.isoformat(),
                "operation": record.operation,
                "files": sorted(files),
                "hashes": hashes if self.config.include_package_hashes else {},
            }
            files["manifest.json"] = json.dumps(
                manifest,
                ensure_ascii=False,
                sort_keys=True,
                indent=2 if self.config.write_pretty_json else None,
            ).encode("utf-8")
            for name, content in files.items():
                destination = temporary / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(content)
            os.replace(temporary, target)
            return StoredFailure(str(target), self.name)
        except OSError as error:
            raise StorageError(str(error)) from error
        finally:
            if temporary.exists():
                shutil.rmtree(temporary, ignore_errors=True)

    def load_files(self, location: str | Path) -> dict[str, bytes]:
        root = Path(location)
        if not root.is_dir():
            raise InvalidPackageError("o caminho não é um diretório TraceSeed")
        output: dict[str, bytes] = {}
        for path in root.rglob("*"):
            if path.is_file():
                output[path.relative_to(root).as_posix()] = path.read_bytes()
        if "manifest.json" not in output:
            raise InvalidPackageError("manifest.json ausente")
        return output
