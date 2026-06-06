from __future__ import annotations

import hashlib
import json
import zipfile
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from traceseed.models import ExceptionInfo


def make_exception_chain(depth: int, *, deepest_message: str) -> BaseException:
    """Return a cause chain with exactly ``depth`` exception objects."""
    if depth < 1:
        raise ValueError("depth must be >= 1")
    current: BaseException = RuntimeError(deepest_message)
    for index in range(depth - 1):
        outer = RuntimeError(f"outer-{index}")
        outer.__cause__ = current
        current = outer
    return current


def walk_exception_info(root: ExceptionInfo | None) -> Iterable[ExceptionInfo]:
    if root is None:
        return
    stack = [root]
    seen: set[int] = set()
    while stack:
        item = stack.pop()
        if id(item) in seen:
            continue
        seen.add(id(item))
        yield item
        if item.cause is not None:
            stack.append(item.cause)
        if item.context is not None:
            stack.append(item.context)
        stack.extend(item.children)


def write_tseed(path: Path, payloads: dict[str, bytes | str]) -> Path:
    """Create a structurally valid v1 package with hashes for all payload files."""
    normalized = {
        name: value.encode("utf-8") if isinstance(value, str) else value
        for name, value in payloads.items()
    }
    manifest = {
        "format": "traceseed",
        "format_version": 1,
        "library_version": "0.1.0",
        "incident_id": "diagnostic-incident",
        "fingerprint": "0" * 32,
        "created_at": "2026-01-01T00:00:00+00:00",
        "operation": "security-diagnostic",
        "files": sorted(normalized),
        "hashes": {
            name: hashlib.sha256(content).hexdigest()
            for name, content in normalized.items()
        },
    }
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in normalized.items():
            archive.writestr(name, content)
        archive.writestr(
            "manifest.json",
            json.dumps(manifest, sort_keys=True).encode("utf-8"),
        )
    return path


def rewrite_zip_member(path: Path, member: str, new_content: bytes | str) -> None:
    """Rewrite one member without updating the package manifest/hashes."""
    replacement = new_content.encode("utf-8") if isinstance(new_content, str) else new_content
    with zipfile.ZipFile(path, "r") as archive:
        entries = {info.filename: archive.read(info.filename) for info in archive.infolist()}
    entries[member] = replacement
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)


def write_raw_zip(path: Path, entries: dict[str, bytes | str]) -> Path:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, value in entries.items():
            archive.writestr(name, value)
    return path


def encoded_list(items: list[Any], *, truncated: bool = False) -> dict[str, Any]:
    return {
        "__traceseed_type__": "list",
        "items": items,
        "truncated": truncated,
    }


def encoded_dict(items: list[list[Any]], *, truncated: bool = False) -> dict[str, Any]:
    return {
        "__traceseed_type__": "dict",
        "items": items,
        "truncated": truncated,
    }
