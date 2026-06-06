"""Hierarquia de exceções do TraceSeed."""

from __future__ import annotations


class ConfigurationError(ValueError):
    """Configuração inválida ou inconsistente."""


class SerializationError(ValueError):
    """Falha ao codificar ou decodificar um valor."""


class StorageError(OSError):
    """Falha ao persistir ou carregar um pacote."""


class IntegrityError(StorageError):
    """Pacote corrompido ou com hash inválido."""


class InvalidPackageError(StorageError):
    """Pacote malformado ou com formato desconhecido."""


class ReplayError(RuntimeError):
    """Falha ao inspecionar ou executar um replay."""
