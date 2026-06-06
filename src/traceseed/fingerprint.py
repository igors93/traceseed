"""Geração de fingerprints normalizadas, estáveis e versionadas.

Versão do algoritmo: 2
Campos incluídos: exception_module, exception_type, message (normalizada),
                  cause_type (tipo da causa imediata), frames (module+function).

Mudança da versão 1 → 2:
- frames usam "module" (ex.: "app.services") em vez de "filename" para
  garantir fingerprints idênticas em máquinas diferentes e entre usuários
  com caminhos absolutos distintos. Quando module não está disponível,
  usa-se os últimos componentes do caminho normalizado como fallback.

Mudanças que exigem incremento de algorithm_version:
- adição/remoção de campos no canonical
- mudança nas regras de normalização
- mudança na política de frames (ex.: incluir linha)
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any

from .config import TraceSeedConfig
from .models import ExceptionInfo, FrameInfo

_ALGORITHM = "traceseed"
_ALGORITHM_VERSION = 2

# Número de caracteres do digest SHA-256 (32 = 128 bits — suficiente para identificação)
_DIGEST_LENGTH = 32

_RE_UUID = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
_RE_HEX = re.compile(r"0x[0-9a-fA-F]+")
_RE_TOKEN = re.compile(r"[A-Za-z0-9]{20,}")
_RE_NUMBER = re.compile(r"\b\d+\b")

# Número de componentes do caminho a manter no fallback (sem módulo disponível)
_PATH_TAIL_COMPONENTS = 3


@dataclass(frozen=True, slots=True)
class FingerprintDetails:
    value: str
    canonical: dict[str, Any]


class Fingerprinter:
    def __init__(self, config: TraceSeedConfig) -> None:
        self.config = config

    def generate(
        self,
        exception: ExceptionInfo,
        frames: tuple[FrameInfo, ...],
    ) -> FingerprintDetails:
        limit = self.config.fingerprint_frame_limit
        selected = frames[-limit:] if limit < len(frames) else frames

        if self.config.normalize_exception_messages:
            message = self.normalize_message(exception.message)
        else:
            message = exception.message

        # Inclui apenas o tipo da causa imediata para estabilidade
        cause_type: str | None = None
        if exception.cause is not None:
            cause_type = f"{exception.cause.module}.{exception.cause.type_name}"

        canonical: dict[str, Any] = {
            "algorithm": _ALGORITHM,
            "algorithm_version": _ALGORITHM_VERSION,
            "exception_module": exception.module,
            "exception_type": exception.type_name,
            "message": message,
            "cause_type": cause_type,
            "frames": [
                {
                    # Usa module (estável entre máquinas) como identificador primário.
                    # Fallback: últimos N componentes do caminho normalizado.
                    "module": (frame.module if frame.module else self._path_tail(frame.filename)),
                    "function": frame.function,
                }
                for frame in selected
            ],
        }
        digest = hashlib.sha256(
            json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()[:_DIGEST_LENGTH]
        return FingerprintDetails(value=digest, canonical=canonical)

    def normalize_message(self, message: str) -> str:
        text = _RE_UUID.sub("<uuid>", message)
        text = _RE_HEX.sub("<hex>", text)
        text = _RE_TOKEN.sub("<token>", text)
        text = _RE_NUMBER.sub("<number>", text)
        return text

    @staticmethod
    def _normalize_path(path: str) -> str:
        """Converte para posix relativo (sem raiz), compatível com Windows e Unix."""
        try:
            parts = PureWindowsPath(path).parts if "\\" in path else PurePosixPath(path).parts
            # Remove âncora raiz ('/', 'C:\\', etc.)
            relative = [
                p for p in parts if p not in ("/", "\\") and not (len(p) == 3 and p[1] == ":")
            ]
            return "/".join(relative) if relative else path
        except Exception:
            return path.lstrip("/\\")

    @classmethod
    def _path_tail(cls, path: str) -> str:
        """Retorna os últimos N componentes do caminho normalizado.

        Usado como fallback quando frame.module não está disponível.
        Garante estabilidade entre máquinas mesmo sem informação de módulo.
        """
        try:
            normalized = cls._normalize_path(path)
            parts = normalized.split("/")
            tail = parts[-_PATH_TAIL_COMPONENTS:]
            return "/".join(tail) if tail else normalized
        except Exception:
            return path
