"""Geração de fingerprints normalizadas e estáveis para exceções."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from .config import TraceSeedConfig
from .models import ExceptionInfo, FrameInfo

_RE_UUID = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
_RE_HEX = re.compile(r"0x[0-9a-fA-F]+")
_RE_TOKEN = re.compile(r"[A-Za-z0-9]{20,}")
_RE_NUMBER = re.compile(r"\b\d+\b")


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

        canonical: dict[str, Any] = {
            "exception_module": exception.module,
            "exception_type": exception.type_name,
            "message": message,
            "frames": [
                {
                    "filename": self._shorten_path(frame.filename),
                    "function": frame.function,
                }
                for frame in selected
            ],
        }
        digest = hashlib.sha256(
            json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()[:32]
        return FingerprintDetails(value=digest, canonical=canonical)

    def normalize_message(self, message: str) -> str:
        text = _RE_UUID.sub("<uuid>", message)
        text = _RE_HEX.sub("<hex>", text)
        text = _RE_TOKEN.sub("<token>", text)
        text = _RE_NUMBER.sub("<number>", text)
        return text

    @staticmethod
    def _shorten_path(path: str) -> str:
        return path.lstrip("/")
