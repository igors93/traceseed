"""Hierarquia de exceções do TraceSeed."""

from __future__ import annotations


class TraceSeedError(Exception):
    """Erro-base para todas as exceções do TraceSeed."""


class ConfigurationError(TraceSeedError, ValueError):
    """Configuração inválida ou inconsistente."""


class SerializationError(TraceSeedError, ValueError):
    """Falha ao codificar ou decodificar um valor."""


class StorageError(TraceSeedError, OSError):
    """Falha ao persistir ou carregar um pacote."""


class IntegrityError(StorageError):
    """Pacote corrompido ou com hash inválido."""


class InvalidPackageError(StorageError):
    """Pacote malformado ou com formato desconhecido."""


class ReplayError(TraceSeedError, RuntimeError):
    """Falha ao inspecionar ou executar um replay."""
