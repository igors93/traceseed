"""TraceSeed public API."""

from __future__ import annotations

__version__ = "0.1.0"

from .api import (
    capture,
    capture_exception,
    get_last_capture,
    guard,
    install,
    install_asyncio,
    register_codec,
    register_collector,
    uninstall,
    uninstall_asyncio,
    unregister_codec,
    unregister_collector,
)
from .config import TraceSeedConfig, configure, get_config, reset_config
from .context import (
    breadcrumb,
    clear_context,
    context,
    current_breadcrumbs,
    current_context,
    reset_context,
    set_context,
)
from .errors import (
    CallbackError,
    ConfigurationError,
    IntegrityError,
    InvalidPackageError,
    ReplayError,
    SerializationError,
    StorageError,
    TraceSeedError,
)
from .logging import BreadcrumbHandler
from .models import (
    Breadcrumb,
    CallableInfo,
    CaptureContext,
    CaptureResult,
    ExceptionInfo,
    FailureRecord,
    FrameInfo,
    RuntimeInfo,
)
from .storage import ArchiveStorage, DirectoryStorage, MemoryStorage, StoredFailure

__all__ = [
    "__version__",
    "capture",
    "capture_exception",
    "get_last_capture",
    "guard",
    "install",
    "install_asyncio",
    "register_codec",
    "register_collector",
    "uninstall",
    "uninstall_asyncio",
    "unregister_codec",
    "unregister_collector",
    "TraceSeedError",
    "CallbackError",
    "ConfigurationError",
    "IntegrityError",
    "InvalidPackageError",
    "ReplayError",
    "SerializationError",
    "StorageError",
    "TraceSeedConfig",
    "configure",
    "get_config",
    "reset_config",
    "breadcrumb",
    "clear_context",
    "context",
    "current_breadcrumbs",
    "current_context",
    "reset_context",
    "set_context",
    "BreadcrumbHandler",
    "Breadcrumb",
    "CallableInfo",
    "CaptureContext",
    "CaptureResult",
    "ExceptionInfo",
    "FailureRecord",
    "FrameInfo",
    "RuntimeInfo",
    "ArchiveStorage",
    "DirectoryStorage",
    "MemoryStorage",
    "StoredFailure",
]
