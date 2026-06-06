from __future__ import annotations

import pytest

from traceseed import TraceSeedConfig
from traceseed.errors import InvalidPackageError
from traceseed.serialization import SafeSerializer
from traceseed.storage import ArchiveStorage

from ._helpers import write_raw_zip


def _storage(tmp_path, **overrides):
    config = TraceSeedConfig(output_directory=tmp_path, **overrides)
    return ArchiveStorage(config, SafeSerializer(config))


@pytest.mark.parametrize(
    "unsafe_name",
    [
        "D:/absolute/path.txt",
        "Z:drive-relative.txt",
        "..\\windows-traversal.txt",
        "safe\\..\\windows-traversal.txt",
    ],
)
def test_windows_style_unsafe_paths_are_rejected_on_all_host_platforms(tmp_path, unsafe_name):
    package = write_raw_zip(tmp_path / "unsafe.tseed", {unsafe_name: "content"})
    with pytest.raises(InvalidPackageError):
        _storage(tmp_path).load_files(package)


def test_mixed_separator_traversal_is_rejected(tmp_path):
    package = write_raw_zip(
        tmp_path / "mixed.tseed",
        {"safe/..\\escape.txt": "content"},
    )
    with pytest.raises(InvalidPackageError):
        _storage(tmp_path).load_files(package)
