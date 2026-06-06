from __future__ import annotations

import json
import zipfile

import pytest

from traceseed import TraceSeedConfig, capture_exception
from traceseed.errors import ConfigurationError, InvalidPackageError
from traceseed.serialization import SafeSerializer
from traceseed.storage import ArchiveStorage


def test_configuration_cannot_generate_a_package_rejected_by_same_library(tmp_path):
    """Either unhashed packages are supported coherently or the option is rejected."""
    try:
        config = TraceSeedConfig(
            output_directory=tmp_path,
            include_package_hashes=False,
        )
    except ConfigurationError:
        return

    storage = ArchiveStorage(config, SafeSerializer(config))
    result = capture_exception(
        RuntimeError("failure"),
        config=config,
        storage=storage,
        strict=True,
    )
    assert result is not None
    storage.verify(result.location)


def test_manifest_hash_policy_is_not_ambiguous_for_generated_packages(tmp_path):
    config = TraceSeedConfig(output_directory=tmp_path)
    storage = ArchiveStorage(config, SafeSerializer(config))
    result = capture_exception(RuntimeError("failure"), config=config, storage=storage, strict=True)
    assert result is not None

    with zipfile.ZipFile(result.location) as archive:
        manifest = json.loads(archive.read("manifest.json"))
    assert manifest["hashes"]
    assert set(manifest["files"]) == set(manifest["hashes"])


def test_archive_storage_rejects_manifest_with_boolean_format_version(tmp_path):
    config = TraceSeedConfig(output_directory=tmp_path)
    storage = ArchiveStorage(config, SafeSerializer(config))
    files = {
        "manifest.json": json.dumps(
            {
                "format": "traceseed",
                "format_version": True,
                "library_version": "0.1.0",
                "files": [],
                "hashes": {},
            }
        ).encode()
    }
    with pytest.raises(InvalidPackageError):
        storage.verify_files(files)
