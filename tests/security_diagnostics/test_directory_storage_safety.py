from __future__ import annotations

import os

import pytest

from traceseed import TraceSeedConfig
from traceseed.errors import InvalidPackageError
from traceseed.serialization import SafeSerializer
from traceseed.storage import DirectoryStorage


def _storage(tmp_path, **overrides):
    config = TraceSeedConfig(output_directory=tmp_path, **overrides)
    return DirectoryStorage(config, SafeSerializer(config))


def _minimal_directory(root):
    root.mkdir()
    (root / "manifest.json").write_text("{}", encoding="utf-8")
    return root


def test_directory_loader_does_not_follow_symlink_outside_package(tmp_path):
    outside = tmp_path / "outside-secret.txt"
    outside.write_text("external-secret", encoding="utf-8")
    package = _minimal_directory(tmp_path / "package")
    link = package / "leak.txt"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available in this environment")

    storage = _storage(tmp_path)
    try:
        files = storage.load_files(package)
    except InvalidPackageError:
        return

    assert "leak.txt" not in files
    assert b"external-secret" not in files.values()


def test_directory_loader_enforces_file_count_limit(tmp_path):
    package = _minimal_directory(tmp_path / "package")
    (package / "one.json").write_text("1", encoding="utf-8")
    (package / "two.json").write_text("2", encoding="utf-8")
    storage = _storage(tmp_path, max_archive_files=2)

    with pytest.raises(InvalidPackageError):
        storage.load_files(package)


def test_directory_loader_enforces_individual_file_size_limit(tmp_path):
    package = _minimal_directory(tmp_path / "package")
    (package / "large.bin").write_bytes(b"x" * 128)
    storage = _storage(
        tmp_path,
        max_archive_file_size=64,
        max_archive_total_size=1024,
        max_manifest_size=64,
    )

    with pytest.raises(InvalidPackageError):
        storage.load_files(package)


def test_directory_loader_enforces_total_size_limit(tmp_path):
    package = _minimal_directory(tmp_path / "package")
    (package / "one.bin").write_bytes(b"x" * 50)
    (package / "two.bin").write_bytes(b"y" * 50)
    storage = _storage(
        tmp_path,
        max_archive_file_size=64,
        max_archive_total_size=96,
        max_manifest_size=64,
    )

    with pytest.raises(InvalidPackageError):
        storage.load_files(package)


def test_directory_loader_rejects_named_pipe_without_blocking(tmp_path):
    if not hasattr(os, "mkfifo"):
        pytest.skip("named pipes are unavailable on this platform")
    package = _minimal_directory(tmp_path / "package")
    pipe = package / "pipe"
    os.mkfifo(pipe)

    # A secure implementation must ignore/reject non-regular files without opening them.
    files = _storage(tmp_path).load_files(package)
    assert "pipe" not in files
