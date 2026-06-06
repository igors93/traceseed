"""Pacote .tseed em ZIP, com manifesto e hashes de integridade.

Garantias de segurança:
- ZIP bomb: metadados verificados ANTES de qualquer leitura de conteúdo.
- Caminhos: absolutos, traversal, diretórios e nomes vazios são rejeitados.
- Entradas: symlinks, diretórios, arquivos criptografados e compressões não
  permitidas são rejeitados por metadados antes de qualquer extração.
- Manifesto: validação integral (formato, versão, files == hashes, sem extras).
- Integridade: SHA-256 verificado após extração.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import zipfile
from contextlib import suppress
from pathlib import Path
from typing import Any, cast

from ..config import TraceSeedConfig
from ..errors import IntegrityError, InvalidPackageError, StorageError
from ..models import FailureRecord
from ..serialization import SafeSerializer
from .base import StoredFailure

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")
_REQUIRED_MANIFEST_FIELDS = frozenset(
    {"format", "format_version", "library_version", "files", "hashes"}
)
_VALID_HASH_RE = re.compile(r"^[0-9a-f]{64}$")

# Compressões permitidas: STORED e DEFLATED
_ALLOWED_COMPRESSION = frozenset({zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED})

# Versões de formato suportadas
_SUPPORTED_FORMAT_VERSIONS = frozenset({1})


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
                with suppress(OSError):
                    temporary.unlink()

    def load_files(self, location: str | Path) -> dict[str, bytes]:
        """Lê arquivo .tseed com proteção contra ZIP bomb e entradas inseguras.

        Ordem de verificação (NUNCA lê conteúdo antes das verificações de metadados):
        1. Abre o ZIP e lê somente ZipInfo (metadados)
        2. Valida quantidade de entradas
        3. Valida nomes e caminhos (absolutos, traversal, vazio)
        4. Rejeita entradas duplicadas
        5. Rejeita tipos inseguros (diretórios, symlinks, criptografados, compressão estranha)
        6. Valida tamanho individual por metadados
        7. Valida tamanho total por metadados
        8. Valida razão de compressão por metadados
        9. Valida tamanho do manifesto por metadados
        10. Somente então lê o conteúdo (com limite real de bytes)
        """
        path = Path(location)
        cfg = self.config
        try:
            with zipfile.ZipFile(path, "r") as archive:
                infos = archive.infolist()

                # 1. Número de entradas
                if len(infos) > cfg.max_archive_files:
                    raise InvalidPackageError(
                        f"pacote contém {len(infos)} arquivos (limite: {cfg.max_archive_files})"
                    )

                # 2. Nomes e caminhos inseguros
                for info in infos:
                    name = info.filename
                    if not name:
                        raise InvalidPackageError("entrada ZIP com nome vazio")
                    if name.startswith("/") or name.startswith("\\"):
                        raise InvalidPackageError(f"caminho absoluto no pacote: {name!r}")
                    if name.startswith("C:") or name.startswith("c:"):
                        raise InvalidPackageError(f"caminho absoluto Windows no pacote: {name!r}")
                    if ".." in Path(name).parts:
                        raise InvalidPackageError(f"caminho com '..' no pacote: {name!r}")

                # 3. Entradas duplicadas
                seen_names: set[str] = set()
                for info in infos:
                    if info.filename in seen_names:
                        raise InvalidPackageError(f"entrada duplicada no ZIP: {info.filename!r}")
                    seen_names.add(info.filename)

                # 4. Tipos inseguros (antes de qualquer leitura)
                for info in infos:
                    name = info.filename
                    # Diretórios (nome termina com '/')
                    if name.endswith("/"):
                        raise InvalidPackageError(f"diretório não permitido no pacote: {name!r}")
                    # Arquivos criptografados (flag bit 0)
                    if info.flag_bits & 0x1:
                        raise InvalidPackageError(f"arquivo criptografado não suportado: {name!r}")
                    # Compressão não permitida
                    if info.compress_type not in _ALLOWED_COMPRESSION:
                        raise InvalidPackageError(
                            f"método de compressão não permitido em {name!r}: {info.compress_type}"
                        )
                    # Symlinks Unix: external_attr contém modo Unix nos bits altos
                    unix_mode = (info.external_attr >> 16) & 0o170000
                    if unix_mode == 0o120000:
                        raise InvalidPackageError(f"symlink não permitido no pacote: {name!r}")

                # 5. Tamanho individual e razão de compressão (por metadados)
                for info in infos:
                    uncompressed = info.file_size
                    compressed = info.compress_size
                    if uncompressed > cfg.max_archive_file_size:
                        raise InvalidPackageError(
                            f"{info.filename!r}: arquivo descompactado muito grande "
                            f"({uncompressed} bytes, limite: {cfg.max_archive_file_size})"
                        )
                    if compressed > 0 and uncompressed / compressed > cfg.max_compression_ratio:
                        raise InvalidPackageError(
                            f"{info.filename!r}: razão de compressão suspeita "
                            f"({uncompressed}/{compressed})"
                        )

                # 6. Tamanho total descompactado
                total_uncompressed = sum(info.file_size for info in infos)
                if total_uncompressed > cfg.max_archive_total_size:
                    raise InvalidPackageError(
                        f"tamanho total descompactado excede limite: "
                        f"{total_uncompressed} bytes (limite: {cfg.max_archive_total_size})"
                    )

                # 7. Tamanho especial do manifesto
                manifest_info = next((i for i in infos if i.filename == "manifest.json"), None)
                if manifest_info and manifest_info.file_size > cfg.max_manifest_size:
                    raise InvalidPackageError(
                        f"manifest.json muito grande: {manifest_info.file_size} bytes "
                        f"(limite: {cfg.max_manifest_size})"
                    )

                # 8. Leitura com limite real de bytes (detecta cabeçalhos mentirosos)
                result: dict[str, bytes] = {}
                for info in infos:
                    limit = cfg.max_archive_file_size
                    with archive.open(info.filename) as fobj:
                        data = fobj.read(limit + 1)
                    if len(data) > limit:
                        raise InvalidPackageError(
                            f"{info.filename!r}: conteúdo real excede limite ({limit} bytes)"
                        )
                    result[info.filename] = data

                return result

        except zipfile.BadZipFile as error:
            raise InvalidPackageError("arquivo não é um pacote .tseed válido") from error
        except (IntegrityError, InvalidPackageError):
            raise
        except OSError as error:
            raise InvalidPackageError(str(error)) from error

    def verify_files(self, files: dict[str, bytes]) -> dict[str, Any]:
        """Valida manifesto e hashes a partir de um dict já carregado.

        Esta é a implementação central de validação — deve ser reutilizada
        por qualquer código que precise verificar um pacote .tseed.
        """
        if "manifest.json" not in files:
            raise InvalidPackageError("manifest.json ausente")

        try:
            raw_manifest = json.loads(files["manifest.json"].decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise InvalidPackageError("manifest.json inválido") from error

        if not isinstance(raw_manifest, dict):
            raise InvalidPackageError("manifest.json deve ser um objeto JSON")

        manifest = raw_manifest

        # Campos obrigatórios
        missing = _REQUIRED_MANIFEST_FIELDS - set(manifest.keys())
        if missing:
            raise InvalidPackageError(f"manifest.json faltam campos: {sorted(missing)}")

        if manifest.get("format") != "traceseed":
            raise InvalidPackageError(f"formato desconhecido: {manifest.get('format')!r}")

        fmt_ver = manifest.get("format_version")
        # bool é subclasse de int — rejeitar explicitamente
        if not isinstance(fmt_ver, int) or isinstance(fmt_ver, bool):
            raise InvalidPackageError("manifest.json: format_version deve ser inteiro (não bool)")
        if fmt_ver not in _SUPPORTED_FORMAT_VERSIONS:
            raise InvalidPackageError(f"manifest.json: format_version {fmt_ver!r} não suportado")

        lib_ver = manifest.get("library_version")
        if not isinstance(lib_ver, str) or not lib_ver.strip():
            raise InvalidPackageError("manifest.json: library_version deve ser string não vazia")

        declared_files = manifest.get("files", [])
        if not isinstance(declared_files, list):
            raise InvalidPackageError("manifest.json: 'files' deve ser lista")
        if not all(isinstance(f, str) for f in declared_files):
            raise InvalidPackageError("manifest.json: 'files' deve conter somente strings")

        # Sem duplicatas em files
        if len(declared_files) != len(set(declared_files)):
            raise InvalidPackageError("manifest.json: 'files' contém entradas duplicadas")

        expected_hashes = manifest.get("hashes", {})
        if not isinstance(expected_hashes, dict):
            raise InvalidPackageError("manifest.json: 'hashes' deve ser objeto")

        # Valida formato dos hashes
        for fname, digest in expected_hashes.items():
            if not isinstance(digest, str) or not _VALID_HASH_RE.match(digest):
                raise InvalidPackageError(
                    f"manifest.json: hash inválido para {fname!r}: {digest!r}"
                )

        # files e hashes devem ter exatamente os mesmos nomes
        files_set = set(declared_files)
        hashes_set = set(expected_hashes.keys())
        if files_set != hashes_set:
            extra_in_hashes = hashes_set - files_set
            missing_hashes = files_set - hashes_set
            parts = []
            if extra_in_hashes:
                parts.append(f"hashes extras: {sorted(extra_in_hashes)}")
            if missing_hashes:
                parts.append(f"arquivos sem hash: {sorted(missing_hashes)}")
            raise InvalidPackageError(
                "manifest.json: 'files' e 'hashes' não coincidem — " + "; ".join(parts)
            )

        # Arquivos reais no pacote devem ser exatamente files + manifest.json
        actual = set(files.keys())
        expected_actual = files_set | {"manifest.json"}
        extra_in_archive = actual - expected_actual
        if extra_in_archive:
            raise InvalidPackageError(
                f"arquivos não declarados no manifesto: {sorted(extra_in_archive)}"
            )
        missing_in_archive = files_set - actual
        if missing_in_archive:
            raise InvalidPackageError(
                f"arquivos declarados ausentes no pacote: {sorted(missing_in_archive)}"
            )

        # Verifica hashes SHA-256
        mismatches = []
        for name, digest in expected_hashes.items():
            actual_digest = hashlib.sha256(files[name]).hexdigest()
            if actual_digest != digest:
                mismatches.append(f"alterado:{name}")
        if mismatches:
            raise IntegrityError(", ".join(mismatches))

        return cast(dict[str, Any], manifest)

    def verify(self, location: str | Path) -> dict[str, Any]:
        """Verifica integridade completa do pacote antes de qualquer uso."""
        files = self.load_files(location)
        return self.verify_files(files)

    def _build_files(self, record: FailureRecord, extra: dict[str, Any]) -> dict[str, bytes]:
        record_data = self.serializer.encode(record)
        files = {
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
            "Note: SHA-256 hashes detect accidental corruption but do NOT authenticate origin.\n"
            "An attacker who can modify the ZIP can also recalculate the hashes.\n"
            "Only replay packages from trusted sources.\n"
        )
