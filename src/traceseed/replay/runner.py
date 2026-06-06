"""Assisted replay with mandatory integrity and schema validation."""

from __future__ import annotations

import importlib
import json
from pathlib import Path
from typing import Any, cast

from ..config import TraceSeedConfig
from ..errors import InvalidPackageError, ReplayError, SerializationError
from ..storage import ArchiveStorage

_REQUIRED_REPLAY_FIELDS = frozenset(
    {"replayable", "module", "qualname", "arguments", "keyword_arguments"}
)


class ReplayRunner:
    def __init__(self, config: TraceSeedConfig | None = None) -> None:
        self.config = config or TraceSeedConfig()
        from ..api import _make_serializer

        self.serializer = _make_serializer(self.config)
        self.storage = ArchiveStorage(self.config, self.serializer)

    def _verify_and_load(
        self,
        package: str | Path,
    ) -> tuple[dict[str, Any], dict[str, bytes]]:
        files = self.storage.load_files(package)
        manifest = self.storage.verify_files(files)
        return manifest, files

    @staticmethod
    def _check_replay_hash(manifest: dict[str, Any]) -> None:
        hashes = manifest.get("hashes")
        if not isinstance(hashes, dict) or "replay.json" not in hashes:
            raise ReplayError("replay.json is not protected by an integrity hash")

    def _load_replay_data(
        self,
        manifest: dict[str, Any],
        files: dict[str, bytes],
    ) -> dict[str, Any]:
        if "replay.json" not in files:
            raise ReplayError("package does not contain replay data")
        self._check_replay_hash(manifest)
        payload = files["replay.json"]
        if len(payload) > self.config.max_replay_payload_size:
            raise ReplayError("replay payload exceeds the configured size limit")
        try:
            value = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise InvalidPackageError("replay.json is invalid") from error
        if not isinstance(value, dict):
            raise InvalidPackageError("replay.json must contain a JSON object")
        return cast(dict[str, Any], value)

    @staticmethod
    def _validate_schema(
        data: dict[str, Any],
        *,
        require_replayable: bool,
    ) -> None:
        replayable = data.get("replayable")
        if not isinstance(replayable, bool):
            raise ReplayError("replayable must be an explicit boolean")
        if replayable is False:
            if require_replayable:
                reason = data.get("reason", "unknown reason")
                raise ReplayError(f"replay is disabled: {reason}")
            return
        missing = _REQUIRED_REPLAY_FIELDS - set(data)
        if missing:
            raise ReplayError(f"replay.json is missing fields: {sorted(missing)}")
        for name in ("module", "qualname"):
            if not isinstance(data.get(name), str) or not data[name].strip():
                raise ReplayError(f"{name} must be a non-empty string")
        if data["module"] == "__main__" or "<locals>" in data["qualname"]:
            raise ReplayError("replay target is not importable")

    def inspect(self, package: str | Path) -> dict[str, Any]:
        manifest, files = self._verify_and_load(package)
        data = self._load_replay_data(manifest, files)
        self._validate_schema(data, require_replayable=False)
        return data

    def run(
        self,
        package: str | Path,
        *,
        allow_code_execution: bool = False,
    ) -> Any:
        if not allow_code_execution:
            raise ReplayError(
                "replay executes application code; explicit authorization is required"
            )
        manifest, files = self._verify_and_load(package)
        data = self._load_replay_data(manifest, files)
        self._validate_schema(data, require_replayable=True)

        try:
            args = self.serializer.decode(data["arguments"], allow_imports=True)
            kwargs = self.serializer.decode(
                data["keyword_arguments"],
                allow_imports=True,
            )
        except SerializationError as error:
            raise ReplayError(str(error)) from error
        except Exception as error:
            raise ReplayError(
                f"unable to decode replay arguments: {type(error).__name__}: {error}"
            ) from error
        if not isinstance(args, (list, tuple)):
            raise ReplayError("positional arguments must decode to a list or tuple")
        if not isinstance(kwargs, dict):
            raise ReplayError("keyword arguments must decode to a dictionary")

        target = self._resolve(data["module"], data["qualname"])
        return target(*args, **kwargs)

    @staticmethod
    def _resolve(module_name: str, qualname: str) -> Any:
        try:
            module = importlib.import_module(module_name)
            target: Any = module
            for part in qualname.split("."):
                if not part or part.startswith("__") or part == "<locals>":
                    raise ReplayError("unsafe replay qualname")
                target = getattr(target, part)
            if not callable(target):
                raise ReplayError("replay target is not callable")
            return target
        except ReplayError:
            raise
        except (ImportError, AttributeError) as error:
            raise ReplayError("unable to import replay target") from error
