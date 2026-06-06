"""Configuração global do TraceSeed."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .errors import ConfigurationError

_DEFAULT_REDACT_FIELDS = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "access_token",
        "refresh_token",
        "private_key",
        "authorization",
        "auth",
        "credential",
        "credentials",
        "ssn",
        "cpf",
        "cnpj",
        "credit_card",
        "card_number",
        "cvv",
        "pin",
    }
)

_DEFAULT_REDACT_PATTERNS = (
    r"Bearer\s+\S+",
    r"\b\d{4}[\s-]\d{4}[\s-]\d{4}[\s-]\d{4}\b",
)


@dataclass(frozen=True, slots=True)
class TraceSeedConfig:
    output_directory: Path = field(default_factory=lambda: Path(".traceseeds"))
    redact_fields: frozenset[str] = field(default_factory=lambda: _DEFAULT_REDACT_FIELDS)
    redact_patterns: tuple[str, ...] = field(default_factory=lambda: _DEFAULT_REDACT_PATTERNS)
    max_value_length: int = 2048
    max_collection_items: int = 64
    max_depth: int = 8
    max_breadcrumbs: int = 100
    max_frames: int = 50
    fingerprint_frame_limit: int = 10
    filename_prefix: str = "failure"
    normalize_exception_messages: bool = True
    capture_locals: bool = False
    re_raise: bool = True
    include_package_hashes: bool = True
    write_pretty_json: bool = True
    # Limites de segurança para leitura de arquivos .tseed
    max_archive_files: int = 256
    max_archive_file_size: int = 50 * 1024 * 1024  # 50 MB descompactado por arquivo
    max_archive_total_size: int = 200 * 1024 * 1024  # 200 MB total descompactado
    max_compression_ratio: int = 200  # razão suspeita de compressão
    max_manifest_size: int = 512 * 1024  # 512 KB para manifest.json

    def __post_init__(self) -> None:
        if isinstance(self.output_directory, str):
            object.__setattr__(self, "output_directory", Path(self.output_directory))
        if self.redact_fields:
            object.__setattr__(
                self,
                "redact_fields",
                frozenset(f.casefold() for f in self.redact_fields),
            )
        if isinstance(self.redact_patterns, (list, tuple)):
            object.__setattr__(self, "redact_patterns", tuple(self.redact_patterns))
        self._validate()

    def _validate(self) -> None:
        if self.max_value_length < 16:
            raise ConfigurationError("max_value_length deve ser >= 16")
        if self.max_collection_items < 1:
            raise ConfigurationError("max_collection_items deve ser >= 1")
        if self.max_depth < 1:
            raise ConfigurationError("max_depth deve ser >= 1")
        if self.max_breadcrumbs < 1:
            raise ConfigurationError("max_breadcrumbs deve ser >= 1")
        if self.max_frames < 1:
            raise ConfigurationError("max_frames deve ser >= 1")
        if self.fingerprint_frame_limit < 1:
            raise ConfigurationError("fingerprint_frame_limit deve ser >= 1")
        if not self.filename_prefix.strip():
            raise ConfigurationError("filename_prefix não pode ser vazio ou só espaços")

    def with_overrides(self, **kwargs: Any) -> TraceSeedConfig:
        fields = {f.name: getattr(self, f.name) for f in self.__dataclass_fields__.values()}
        fields.update(kwargs)
        return TraceSeedConfig(**fields)

    def with_redact_fields(self, extra: list[str]) -> TraceSeedConfig:
        new_fields = self.redact_fields | frozenset(f.casefold() for f in extra)
        return self.with_overrides(redact_fields=new_fields)


_current_config: TraceSeedConfig | None = None


def get_config() -> TraceSeedConfig:
    global _current_config
    if _current_config is None:
        _current_config = TraceSeedConfig()
    return _current_config


def configure(config: TraceSeedConfig | None = None, **overrides: Any) -> TraceSeedConfig:
    global _current_config
    if config is not None and not isinstance(config, TraceSeedConfig):
        raise TypeError(f"esperado TraceSeedConfig, mas recebeu {type(config).__name__}")
    if config is None:
        config = TraceSeedConfig()
    if overrides:
        config = config.with_overrides(**overrides)
    _current_config = config
    return config


def reset_config() -> TraceSeedConfig:
    global _current_config
    _current_config = TraceSeedConfig()
    return _current_config
