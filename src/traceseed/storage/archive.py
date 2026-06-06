"""Versioned .tseed ZIP storage with strict integrity and resource limits."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
import zipfile
from contextlib import suppress
from pathlib import Path, PurePosixPath
from typing import Any, cast

from ..config import TraceSeedConfig
from ..errors import IntegrityError, InvalidPackageError, StorageError
from ..models import FailureRecord
from ..serialization import SafeSerializer
from .base import StoredFailure

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")
_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:")
_REQUIRED_MANIFEST_FIELDS = frozenset(
    {"format", "format_version", "library_version", "files", "hashes"}
)
_VALID_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_ALLOWED_COMPRESSION = frozenset({zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED})
_SUPPORTED_FORMAT_VERSIONS = frozenset({1})


class ArchiveStorage:
    name = "archive"

    def __init__(self, config: TraceSeedConfig, serializer: SafeSerializer) -> None:
        self.config = config
        self.serializer = serializer

    def save(
        self,
        record: FailureRecord,
        extra: dict[str, Any] | None = None,
    ) -> StoredFailure:
        directory = self.config.output_directory
        try:
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        except OSError as error:
            raise StorageError(f"unable to create {directory}: {error}") from error

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
            "hashes": hashes,
        }
        files["manifest.json"] = self._json_bytes(manifest)

        target = directory / self._filename(record)
        temporary: Path | None = None
        try:
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=".traceseed-",
                suffix=".tmp",
                dir=directory,
            )
            os.close(descriptor)
            temporary = Path(temporary_name)
            os.chmod(temporary, 0o600)
            with zipfile.ZipFile(
                temporary,
                mode="w",
                compression=zipfile.ZIP_DEFLATED,
            ) as archive:
                for name in sorted(files):
                    info = zipfile.ZipInfo(name)
                    info.date_time = (1980, 1, 1, 0, 0, 0)
                    info.compress_type = zipfile.ZIP_DEFLATED
                    info.external_attr = (stat.S_IFREG | 0o600) << 16
                    archive.writestr(info, files[name])
            os.replace(temporary, target)
            os.chmod(target, 0o600)
            return StoredFailure(location=str(target), storage_name=self.name)
        except (OSError, zipfile.BadZipFile) as error:
            raise StorageError(f"unable to save package: {error}") from error
        finally:
            if temporary is not None and temporary.exists():
                with suppress(OSError):
                    temporary.unlink()

    def load_files(self, location: str | Path) -> dict[str, bytes]:
        path = Path(location)
        config = self.config
        try:
            with zipfile.ZipFile(path, "r") as archive:
                infos = archive.infolist()
                if len(infos) > config.max_archive_files:
                    raise InvalidPackageError(
                        f"package contains {len(infos)} files; limit is {config.max_archive_files}"
                    )

                seen: set[str] = set()
                total_metadata_size = 0
                for info in infos:
                    name = self._validate_member_name(info.filename)
                    if name in seen:
                        raise InvalidPackageError(f"duplicate ZIP entry: {name!r}")
                    seen.add(name)
                    self._validate_member_type(info)
                    if info.file_size > config.max_archive_file_size:
                        raise InvalidPackageError(f"{name!r} exceeds the per-file size limit")
                    if info.file_size > 0 and info.compress_size == 0:
                        raise InvalidPackageError(f"{name!r} has invalid compressed size metadata")
                    if (
                        info.compress_size > 0
                        and info.file_size / info.compress_size > config.max_compression_ratio
                    ):
                        raise InvalidPackageError(f"{name!r} exceeds the compression ratio limit")
                    total_metadata_size += info.file_size
                    if total_metadata_size > config.max_archive_total_size:
                        raise InvalidPackageError(
                            "package exceeds the total uncompressed size limit"
                        )
                    if name == "manifest.json" and info.file_size > config.max_manifest_size:
                        raise InvalidPackageError("manifest.json exceeds its size limit")

                result: dict[str, bytes] = {}
                total_actual_size = 0
                for info in infos:
                    name = self._validate_member_name(info.filename)
                    limit = (
                        config.max_manifest_size
                        if name == "manifest.json"
                        else config.max_archive_file_size
                    )
                    with archive.open(info, "r") as stream:
                        data = stream.read(limit + 1)
                    if len(data) > limit:
                        raise InvalidPackageError(f"{name!r} exceeds its actual size limit")
                    total_actual_size += len(data)
                    if total_actual_size > config.max_archive_total_size:
                        raise InvalidPackageError("package exceeds the actual total size limit")
                    result[name] = data
                return result
        except zipfile.BadZipFile as error:
            raise InvalidPackageError("file is not a valid .tseed package") from error
        except (IntegrityError, InvalidPackageError):
            raise
        except OSError as error:
            raise InvalidPackageError(str(error)) from error

    @staticmethod
    def _validate_member_name(raw_name: str) -> str:
        if not isinstance(raw_name, str) or not raw_name or "\x00" in raw_name:
            raise InvalidPackageError("ZIP entry has an invalid name")
        normalized = raw_name.replace("\\", "/")
        if normalized.startswith(("/", "//")) or _WINDOWS_DRIVE.match(normalized):
            raise InvalidPackageError(f"absolute path in package: {raw_name!r}")
        parts = PurePosixPath(normalized).parts
        if not parts or any(part in {"", ".", ".."} for part in parts):
            raise InvalidPackageError(f"unsafe path in package: {raw_name!r}")
        canonical = "/".join(parts)
        if canonical != normalized:
            raise InvalidPackageError(f"non-canonical path in package: {raw_name!r}")
        return canonical

    @staticmethod
    def _validate_member_type(info: zipfile.ZipInfo) -> None:
        name = info.filename
        if name.endswith("/") or info.is_dir():
            raise InvalidPackageError(f"directories are not allowed: {name!r}")
        if info.flag_bits & 0x1:
            raise InvalidPackageError(f"encrypted entries are not supported: {name!r}")
        if info.compress_type not in _ALLOWED_COMPRESSION:
            raise InvalidPackageError(f"unsupported compression method for {name!r}")
        unix_mode = (info.external_attr >> 16) & 0o170000
        if unix_mode and unix_mode != stat.S_IFREG:
            raise InvalidPackageError(f"non-regular ZIP entry is not allowed: {name!r}")

    def verify_files(self, files: dict[str, bytes]) -> dict[str, Any]:
        if not isinstance(files, dict) or not all(
            isinstance(name, str) and isinstance(content, bytes) for name, content in files.items()
        ):
            raise InvalidPackageError("package files must be a string-to-bytes mapping")
        if "manifest.json" not in files:
            raise InvalidPackageError("manifest.json is missing")
        try:
            manifest_value = json.loads(files["manifest.json"].decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise InvalidPackageError("manifest.json is invalid") from error
        if not isinstance(manifest_value, dict):
            raise InvalidPackageError("manifest.json must contain a JSON object")
        manifest = manifest_value

        missing_fields = _REQUIRED_MANIFEST_FIELDS - set(manifest)
        if missing_fields:
            raise InvalidPackageError(f"manifest.json is missing fields: {sorted(missing_fields)}")
        if manifest.get("format") != "traceseed":
            raise InvalidPackageError("unknown package format")
        format_version = manifest.get("format_version")
        if not isinstance(format_version, int) or isinstance(format_version, bool):
            raise InvalidPackageError("format_version must be an integer, not bool")
        if format_version not in _SUPPORTED_FORMAT_VERSIONS:
            raise InvalidPackageError(f"unsupported format_version: {format_version!r}")
        library_version = manifest.get("library_version")
        if not isinstance(library_version, str) or not library_version.strip():
            raise InvalidPackageError("library_version must be a non-empty string")

        declared_files = manifest.get("files")
        expected_hashes = manifest.get("hashes")
        if not isinstance(declared_files, list) or not all(
            isinstance(name, str) for name in declared_files
        ):
            raise InvalidPackageError("manifest files must be a list of strings")
        if len(declared_files) != len(set(declared_files)):
            raise InvalidPackageError("manifest files contains duplicates")
        if not isinstance(expected_hashes, dict) or not all(
            isinstance(name, str) and isinstance(digest, str) and _VALID_HASH_RE.fullmatch(digest)
            for name, digest in expected_hashes.items()
        ):
            raise InvalidPackageError("manifest hashes are invalid")

        declared_set = set(declared_files)
        hash_set = set(expected_hashes)
        if declared_set != hash_set:
            raise InvalidPackageError("manifest files and hashes must match exactly")
        actual_set = set(files)
        expected_actual = declared_set | {"manifest.json"}
        if actual_set != expected_actual:
            raise InvalidPackageError("archive members do not match the manifest")

        mismatches = [
            name
            for name, digest in expected_hashes.items()
            if hashlib.sha256(files[name]).hexdigest() != digest
        ]
        if mismatches:
            raise IntegrityError(
                "package integrity check failed for: " + ", ".join(sorted(mismatches))
            )
        return cast(dict[str, Any], manifest)

    def verify(self, location: str | Path) -> dict[str, Any]:
        return self.verify_files(self.load_files(location))

    def _build_files(
        self,
        record: FailureRecord,
        extra: dict[str, Any],
    ) -> dict[str, bytes]:
        record_data = self.serializer.encode(record)
        files: dict[str, bytes] = {
            "summary.json": self._json_bytes(
                {
                    "incident_id": record.incident_id,
                    "fingerprint": record.fingerprint,
                    "created_at": record.created_at.isoformat(),
                    "operation": record.operation,
                    "exception": {
                        "module": record.exception.module,
                        "type_name": record.exception.type_name,
                        "message": record.exception.message,
                    },
                    "top_frame": (
                        {
                            "filename": record.frames[-1].filename,
                            "function": record.frames[-1].function,
                            "line_number": record.frames[-1].line_number,
                        }
                        if record.frames
                        else None
                    ),
                    "collector_errors": list(record.collector_errors),
                    "extension_keys": sorted(record.extensions),
                    "replayable": bool(record.callable_info and record.callable_info.replayable),
                }
            ),
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
        if traceback_text is not None:
            files["traceback.txt"] = str(traceback_text).encode("utf-8", errors="replace")
        if extra.get("fingerprint_canonical") is not None:
            files["fingerprint-canonical.json"] = self._json_bytes(extra["fingerprint_canonical"])
        if extra.get("threads"):
            files["threads.json"] = self._json_bytes(self.serializer.encode(extra["threads"]))
        if extra.get("replay") is not None:
            files["replay.json"] = self._json_bytes(extra["replay"])
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
        safe_operation = _SAFE_NAME.sub("-", operation).strip("-._") or "failure"
        safe_incident = _SAFE_NAME.sub("-", record.incident_id).strip("-._") or "incident"
        return f"{safe_operation}-{record.fingerprint}-{safe_incident}.tseed"

    @staticmethod
    def _readme(record: FailureRecord) -> str:
        return (
            "TraceSeed diagnostic package\n"
            "============================\n\n"
            f"Incident: {record.incident_id}\n"
            f"Fingerprint: {record.fingerprint}\n"
            f"Exception: {record.exception.type_name}: {record.exception.message}\n\n"
            "Security warning: this package may contain application data.\n"
            "SHA-256 hashes detect corruption but do not authenticate origin.\n"
            "Never replay a package received from an untrusted source.\n"
        )
