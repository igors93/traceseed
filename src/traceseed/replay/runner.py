"""Reprodução assistida. Executa código somente com autorização explícita."""

from __future__ import annotations

import importlib
import json
from pathlib import Path
from typing import Any

from ..config import TraceSeedConfig
from ..errors import InvalidPackageError, ReplayError, SerializationError
from ..serialization import SafeSerializer
from ..storage import ArchiveStorage


class ReplayRunner:
    def __init__(self, config: TraceSeedConfig | None = None) -> None:
        self.config = config or TraceSeedConfig()
        self.serializer = SafeSerializer(self.config)
        self.storage = ArchiveStorage(self.config, self.serializer)

    def inspect(self, package: str | Path) -> dict[str, Any]:
        files = self.storage.load_files(package)
        if "replay.json" not in files:
            raise ReplayError("o pacote não contém dados de replay")
        try:
            return json.loads(files["replay.json"].decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise InvalidPackageError("replay.json inválido") from error

    def run(self, package: str | Path, *, allow_code_execution: bool = False) -> Any:
        if not allow_code_execution:
            raise ReplayError(
                "replay executa código da aplicação; use allow_code_execution=True somente em pacote confiável"
            )
        data = self.inspect(package)
        target = self._resolve(data["module"], data["qualname"])
        try:
            args = self.serializer.decode(data["arguments"], allow_imports=True)
            kwargs = self.serializer.decode(data["keyword_arguments"], allow_imports=True)
        except SerializationError as error:
            raise ReplayError(str(error)) from error
        if not isinstance(args, (list, tuple)):
            raise ReplayError("argumentos posicionais inválidos")
        if not isinstance(kwargs, dict):
            raise ReplayError("argumentos nomeados inválidos")
        return target(*args, **kwargs)

    @staticmethod
    def _resolve(module_name: str, qualname: str) -> Any:
        if module_name in {"", "__main__"} or "<locals>" in qualname:
            raise ReplayError("callable não importável")
        try:
            module = importlib.import_module(module_name)
            target: Any = module
            for part in qualname.split("."):
                if part.startswith("__"):
                    raise ReplayError("qualname inseguro")
                target = getattr(target, part)
            if not callable(target):
                raise ReplayError("alvo do replay não é chamável")
            return target
        except (ImportError, AttributeError) as error:
            raise ReplayError(f"não foi possível importar callable: {error}") from error
