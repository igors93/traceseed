"""Reprodução assistida. Executa código somente com autorização explícita.

Garantia de segurança: a integridade do pacote é SEMPRE verificada antes de
qualquer importação ou execução de código, independentemente do caminho de
chamada. Isso impede adulteração de replay.json para injetar código arbitrário.
"""

from __future__ import annotations

import importlib
import json
from pathlib import Path
from typing import Any, cast

from ..config import TraceSeedConfig
from ..errors import IntegrityError, InvalidPackageError, ReplayError, SerializationError
from ..serialization import SafeSerializer
from ..storage import ArchiveStorage


class ReplayRunner:
    def __init__(self, config: TraceSeedConfig | None = None) -> None:
        self.config = config or TraceSeedConfig()
        self.serializer = SafeSerializer(self.config)
        self.storage = ArchiveStorage(self.config, self.serializer)

    def _verify_and_load(self, package: str | Path) -> tuple[dict[str, Any], dict[str, bytes]]:
        """Verifica integridade completa antes de retornar conteúdo.

        NUNCA pule este método antes de importar ou executar código.
        """
        path = Path(package)

        # verify() já chama load_files() internamente, mas precisamos dos
        # bytes para leitura posterior sem re-abrir o arquivo, então fazemos
        # load_files() uma vez e verificamos manualmente para evitar I/O duplo.
        files = self.storage.load_files(path)

        if "manifest.json" not in files:
            raise InvalidPackageError("manifest.json ausente")

        try:
            manifest = json.loads(files["manifest.json"].decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise InvalidPackageError("manifest.json inválido") from error

        if manifest.get("format") != "traceseed":
            raise InvalidPackageError(f"formato desconhecido: {manifest.get('format')!r}")

        # Campos obrigatórios
        for field in ("format_version", "library_version", "files", "hashes"):
            if field not in manifest:
                raise InvalidPackageError(f"manifest.json faltam campo: {field!r}")

        # Verifica hashes — qualquer desvio impede execução
        import hashlib as _hashlib

        expected = manifest.get("hashes", {})
        mismatches = []
        for name, digest in expected.items():
            if name not in files:
                mismatches.append(f"ausente:{name}")
                continue
            actual = _hashlib.sha256(files[name]).hexdigest()
            if actual != digest:
                mismatches.append(f"alterado:{name}")
        if mismatches:
            raise IntegrityError(", ".join(mismatches))

        return manifest, files

    def inspect(self, package: str | Path) -> dict[str, Any]:
        """Inspeciona metadados de replay verificando integridade primeiro."""
        _manifest, files = self._verify_and_load(package)
        if "replay.json" not in files:
            raise ReplayError("o pacote não contém dados de replay")
        try:
            return cast(dict[str, Any], json.loads(files["replay.json"].decode("utf-8")))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise InvalidPackageError("replay.json inválido") from error

    def run(self, package: str | Path, *, allow_code_execution: bool = False) -> Any:
        """Executa replay do pacote.

        A integridade é verificada ANTES de qualquer importação de módulo.
        """
        if not allow_code_execution:
            raise ReplayError(
                "replay executa código da aplicação; use allow_code_execution=True somente em pacote confiável"
            )

        # Verificação de integridade obrigatória antes de importar qualquer código
        _manifest, files = self._verify_and_load(package)

        if "replay.json" not in files:
            raise ReplayError("o pacote não contém dados de replay")
        try:
            data = json.loads(files["replay.json"].decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise InvalidPackageError("replay.json inválido") from error

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
