"""Pacote .tseed em ZIP, com manifesto e hashes de integridade."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import zipfile
from dataclasses import asdict, is_dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from ..config import TraceSeedConfig
from ..errors import IntegrityError, InvalidPackageError, StorageError
from ..models import FailureRecord
from ..serialization import SafeSerializer
from .base import StoredFailure

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


class ArchiveStorage:
    name = "archive"

    def __init__(self, config: TraceSeedConfig, serializer: SafeSerializer) -> None:
        self.config = config
        self.serializer = serializer

    def save(self, record: FailureRecord, extra: dict[str, Any] | None = None) -> StoredFailure:
        directory = self.config.output_directory
        try:
            directory.mkdir(parents=True, exist_ok=True)
        except OSError as error:
            raise StorageError(f"não foi possível criar {directory}: {error}") from error

        files = self._build_files(record, extra or {})
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
        files["manifest.json"] = self._json_bytes(manifest)

        filename = self._filename(record)
        target = directory / filename
        temporary: Path | None = None
        try:
            fd, temp_name = tempfile.mkstemp(prefix=".traceseed-", suffix=".tmp", dir=directory)
            os.close(fd)
            temporary = Path(temp_name)
            with zipfile.ZipFile(temporary, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
                for name in sorted(files):
                    info = zipfile.ZipInfo(name)
                    info.date_time = (1980, 1, 1, 0, 0, 0)
                    info.compress_type = zipfile.ZIP_DEFLATED
                    info.external_attr = 0o600 << 16
                    archive.writestr(info, files[name])
            os.replace(temporary, target)
            return StoredFailure(location=str(target), storage_name=self.name)
        except OSError as error:
            raise StorageError(f"não foi possível salvar pacote: {error}") from error
        finally:
            if temporary is not None and temporary.exists():
                try:
                    temporary.unlink()
                except OSError:
                    pass

    def load_files(self, location: str | Path) -> dict[str, bytes]:
        path = Path(location)
        try:
            with zipfile.ZipFile(path, "r") as archive:
                bad = archive.testzip()
                if bad:
                    raise IntegrityError(f"arquivo ZIP corrompido: {bad}")
                names = archive.namelist()
                if any(name.startswith("/") or ".." in Path(name).parts for name in names):
                    raise InvalidPackageError("pacote contém caminho inseguro")
                return {name: archive.read(name) for name in names}
        except zipfile.BadZipFile as error:
            raise InvalidPackageError("arquivo não é um pacote .tseed válido") from error
        except OSError as error:
            raise InvalidPackageError(str(error)) from error

    def verify(self, location: str | Path) -> dict[str, Any]:
        files = self.load_files(location)
        if "manifest.json" not in files:
            raise InvalidPackageError("manifest.json ausente")
        try:
            manifest = json.loads(files["manifest.json"].decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise InvalidPackageError("manifest.json inválido") from error
        if manifest.get("format") != "traceseed":
            raise InvalidPackageError("formato desconhecido")
        expected = manifest.get("hashes", {})
        mismatches = []
        for name, digest in expected.items():
            if name not in files:
                mismatches.append(f"ausente:{name}")
                continue
            actual = hashlib.sha256(files[name]).hexdigest()
            if actual != digest:
                mismatches.append(f"alterado:{name}")
        if mismatches:
            raise IntegrityError(", ".join(mismatches))
        return manifest

    def _build_files(self, record: FailureRecord, extra: dict[str, Any]) -> dict[str, bytes]:
        record_data = self.serializer.encode(record)
        files = {
            "summary.json": self._json_bytes({
                "incident_id": record.incident_id,
                "fingerprint": record.fingerprint,
                "created_at": record.created_at.isoformat(),
                "operation": record.operation,
                "exception": {
                    "module": record.exception.module,
                    "type_name": record.exception.type_name,
                    "message": record.exception.message,
                },
                "top_frame": ({
                    "filename": record.frames[-1].filename,
                    "function": record.frames[-1].function,
                    "line_number": record.frames[-1].line_number,
                } if record.frames else None),
                "collector_errors": list(record.collector_errors),
                "extension_keys": sorted(record.extensions),
                "replayable": bool(record.callable_info and record.callable_info.replayable),
            }),
            "record.json": self._json_bytes(record_data),
            "exception.json": self._json_bytes(self.serializer.encode(record.exception)),
            "traceback.json": self._json_bytes(self.serializer.encode(record.frames)),
            "runtime.json": self._json_bytes(self.serializer.encode(record.runtime)),
            "arguments.json": self._json_bytes(self.serializer.encode(record.arguments)),
            "metadata.json": self._json_bytes(self.serializer.encode(record.metadata)),
            "extensions.json": self._json_bytes(self.serializer.encode(record.extensions)),
            "breadcrumbs.json": self._json_bytes(self.serializer.encode(record.breadcrumbs)),
            "fingerprint.json": self._json_bytes(
                {
                    "fingerprint": record.fingerprint,
                    "incident_id": record.incident_id,
                }
            ),
            "README.txt": self._readme(record).encode("utf-8"),
        }
        traceback_text = extra.get("traceback_text")
        if traceback_text:
            files["traceback.txt"] = str(traceback_text).encode("utf-8", errors="replace")
        if extra.get("fingerprint_canonical") is not None:
            files["fingerprint-canonical.json"] = self._json_bytes(extra["fingerprint_canonical"])
        if extra.get("threads"):
            files["threads.json"] = self._json_bytes(self.serializer.encode(extra["threads"]))
        replay = extra.get("replay")
        if replay:
            files["replay.json"] = self._json_bytes(replay)
        return files

    def _json_bytes(self, value: Any) -> bytes:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            indent=2 if self.config.write_pretty_json else None,
            separators=None if self.config.write_pretty_json else (",", ":"),
        ).encode("utf-8")

    def _filename(self, record: FailureRecord) -> str:
        operation = record.operation or self.config.filename_prefix
        operation = _SAFE_NAME.sub("-", operation).strip("-._") or "failure"
        short_id = record.incident_id.split("-")[0]
        return f"{operation}-{record.fingerprint}-{short_id}.tseed"

    @staticmethod
    def _readme(record: FailureRecord) -> str:
        return (
            "TraceSeed diagnostic package\n"
            "============================\n\n"
            f"Incident: {record.incident_id}\n"
            f"Fingerprint: {record.fingerprint}\n"
            f"Exception: {record.exception.type_name}: {record.exception.message}\n\n"
            "Security warning: a package may contain application data. Review it before sharing.\n"
            "Never replay a package received from an untrusted source.\n"
        )
