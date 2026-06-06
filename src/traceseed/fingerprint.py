"""Stable, versioned failure fingerprint generation."""

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
_DIGEST_LENGTH = 32
_PATH_TAIL_COMPONENTS = 3
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
        selected = frames[-self.config.fingerprint_frame_limit :]
        message = (
            self.normalize_message(exception.message)
            if self.config.normalize_exception_messages
            else exception.message
        )
        cause_type = None
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
                    "module": frame.module or self._path_tail(frame.filename),
                    "function": frame.function,
                }
                for frame in selected
            ],
        }
        digest = hashlib.sha256(
            json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()[:_DIGEST_LENGTH]
        return FingerprintDetails(value=digest, canonical=canonical)

    @staticmethod
    def normalize_message(message: str) -> str:
        text = _RE_UUID.sub("<uuid>", message)
        text = _RE_HEX.sub("<hex>", text)
        text = _RE_TOKEN.sub("<token>", text)
        return _RE_NUMBER.sub("<number>", text)

    @staticmethod
    def _normalize_path(path: str) -> str:
        try:
            parts = PureWindowsPath(path).parts if "\\" in path else PurePosixPath(path).parts
            relative = [
                part
                for part in parts
                if part not in ("/", "\\") and not (len(part) >= 2 and part[1] == ":")
            ]
            return "/".join(relative) if relative else path
        except Exception:
            return path.lstrip("/\\")

    @classmethod
    def _path_tail(cls, path: str) -> str:
        normalized = cls._normalize_path(path)
        parts = normalized.split("/")
        return "/".join(parts[-_PATH_TAIL_COMPONENTS:])
