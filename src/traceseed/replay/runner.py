"""Reprodução assistida. Executa código somente com autorização explícita.

Garantia de segurança: a integridade do pacote é SEMPRE verificada antes de
qualquer importação ou execução de código. A verificação é centralizada em
ArchiveStorage.verify_files() para evitar duplicação de regras.

Replay é bloqueado quando:
- hashes estão ausentes ou incompletos;
- replay.json não possui hash;
- qualquer arquivo foi adulterado;
- replay.json declara replayable=false.
"""

from __future__ import annotations

import importlib
import json
from pathlib import Path
from typing import Any, cast

from ..config import TraceSeedConfig
from ..errors import InvalidPackageError, ReplayError, SerializationError
from ..serialization import SafeSerializer
from ..storage import ArchiveStorage


class ReplayRunner:
    def __init__(self, config: TraceSeedConfig | None = None) -> None:
        self.config = config or TraceSeedConfig()
        self.serializer = SafeSerializer(self.config)
        self.storage = ArchiveStorage(self.config, self.serializer)

    def _verify_and_load(self, package: str | Path) -> tuple[dict[str, Any], dict[str, bytes]]:
        """Verifica integridade completa antes de retornar conteúdo.

        Delega toda a lógica de validação para ArchiveStorage — sem duplicação
        de regras de manifesto. NUNCA pule este método antes de importar ou
        executar código.
        """
        path = Path(package)
        files = self.storage.load_files(path)
        manifest = self.storage.verify_files(files)
        return manifest, files

    def _check_replay_hash(self, manifest: dict[str, Any]) -> None:
        """Garante que replay.json possui hash — bloqueia replay sem integridade."""
        hashes = manifest.get("hashes", {})
        if not hashes:
            raise ReplayError("replay requer hashes de integridade (include_package_hashes=True)")
        if "replay.json" not in hashes:
            raise ReplayError("replay.json não possui hash — integridade não garantida")

    def inspect(self, package: str | Path) -> dict[str, Any]:
        """Inspeciona metadados de replay verificando integridade primeiro."""
        manifest, files = self._verify_and_load(package)
        if "replay.json" not in files:
            raise ReplayError("o pacote não contém dados de replay")
        self._check_replay_hash(manifest)
        try:
            return cast(dict[str, Any], json.loads(files["replay.json"].decode("utf-8")))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise InvalidPackageError("replay.json inválido") from error

    def run(self, package: str | Path, *, allow_code_execution: bool = False) -> Any:
        """Executa replay do pacote.

        A integridade é verificada ANTES de qualquer importação de módulo.
        Replay com argumentos redigidos ou marcados como não reproduzíveis é bloqueado.
        """
        if not allow_code_execution:
            raise ReplayError(
                "replay executa código da aplicação; use allow_code_execution=True somente em pacote confiável"
            )

        # Verificação de integridade obrigatória — nenhum import antes daqui
        manifest, files = self._verify_and_load(package)

        if "replay.json" not in files:
            raise ReplayError("o pacote não contém dados de replay")

        self._check_replay_hash(manifest)

        try:
            data = cast(dict[str, Any], json.loads(files["replay.json"].decode("utf-8")))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise InvalidPackageError("replay.json inválido") from error

        # Verifica flag replayable (novo formato) — backward compat: ausente = True
        if not data.get("replayable", True):
            reason = data.get("reason", "unknown")
            raise ReplayError(f"replay desabilitado: {reason}")

        # Só importa/executa código depois da verificação aprovada
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
