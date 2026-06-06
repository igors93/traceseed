"""Inspectable directory storage with the same limits as archive storage."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
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

    def save(
        self,
        record: FailureRecord,
        extra: dict[str, Any] | None = None,
    ) -> StoredFailure:
        root = self.config.output_directory
        try:
            root.mkdir(parents=True, exist_ok=True, mode=0o700)
        except OSError as error:
            raise StorageError(str(error)) from error
        operation = _SAFE_NAME.sub("-", record.operation or "failure").strip("-._") or "failure"
        incident = _SAFE_NAME.sub("-", record.incident_id).strip("-._") or "incident"
        target = root / f"{operation}-{record.fingerprint}-{incident}"
        temporary = Path(tempfile.mkdtemp(prefix=".traceseed-", dir=root))
        os.chmod(temporary, 0o700)
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
                "hashes": hashes,
            }
            files["manifest.json"] = json.dumps(
                manifest,
                ensure_ascii=False,
                sort_keys=True,
                indent=2 if self.config.write_pretty_json else None,
            ).encode("utf-8")
            for name, content in files.items():
                destination = temporary / name
                destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                destination.write_bytes(content)
                os.chmod(destination, 0o600)
            os.replace(temporary, target)
            return StoredFailure(location=str(target), storage_name=self.name)
        except OSError as error:
            raise StorageError(str(error)) from error
        finally:
            if temporary.exists():
                shutil.rmtree(temporary, ignore_errors=True)

    def load_files(self, location: str | Path) -> dict[str, bytes]:
        root = Path(location)
        try:
            root_stat = root.lstat()
        except OSError as error:
            raise InvalidPackageError(str(error)) from error
        if not stat.S_ISDIR(root_stat.st_mode) or root.is_symlink():
            raise InvalidPackageError("path is not a regular TraceSeed directory")

        files: dict[str, bytes] = {}
        total_size = 0
        stack = [root]
        while stack:
            current = stack.pop()
            try:
                entries = list(os.scandir(current))
            except OSError as error:
                raise InvalidPackageError(str(error)) from error
            for entry in entries:
                try:
                    entry_stat = entry.stat(follow_symlinks=False)
                except OSError as error:
                    raise InvalidPackageError(str(error)) from error
                if stat.S_ISLNK(entry_stat.st_mode):
                    continue
                if stat.S_ISDIR(entry_stat.st_mode):
                    stack.append(Path(entry.path))
                    continue
                if not stat.S_ISREG(entry_stat.st_mode):
                    continue

                relative = Path(entry.path).relative_to(root).as_posix()
                if relative in files:
                    raise InvalidPackageError(f"duplicate file: {relative!r}")
                if len(files) + 1 > self.config.max_archive_files:
                    raise InvalidPackageError("directory package exceeds the file count limit")
                limit = (
                    self.config.max_manifest_size
                    if relative == "manifest.json"
                    else self.config.max_archive_file_size
                )
                if entry_stat.st_size > limit:
                    raise InvalidPackageError(f"{relative!r} exceeds its size limit")
                total_size += entry_stat.st_size
                if total_size > self.config.max_archive_total_size:
                    raise InvalidPackageError("directory package exceeds the total size limit")
                try:
                    with open(entry.path, "rb") as stream:
                        data = stream.read(limit + 1)
                except OSError as error:
                    raise InvalidPackageError(str(error)) from error
                if len(data) > limit:
                    raise InvalidPackageError(f"{relative!r} exceeds its actual size limit")
                files[relative] = data

        if "manifest.json" not in files:
            raise InvalidPackageError("manifest.json is missing")
        return files

    def verify(self, location: str | Path) -> dict[str, Any]:
        return self._archive_helper.verify_files(self.load_files(location))
