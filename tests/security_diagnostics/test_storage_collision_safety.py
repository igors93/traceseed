from __future__ import annotations

from dataclasses import replace

from traceseed import MemoryStorage, TraceSeedConfig, capture_exception
from traceseed.serialization import SafeSerializer
from traceseed.storage import ArchiveStorage, DirectoryStorage


def _two_records_with_same_short_id():
    memory = MemoryStorage()
    first = capture_exception(RuntimeError("failure"), storage=memory, strict=True).record
    second = replace(
        first,
        incident_id="deadbeef-1111-1111-1111-111111111111",
    )
    first = replace(
        first,
        incident_id="deadbeef-2222-2222-2222-222222222222",
    )
    return first, second


def test_archive_filenames_do_not_collide_on_uuid_prefix(tmp_path):
    config = TraceSeedConfig(output_directory=tmp_path)
    storage = ArchiveStorage(config, SafeSerializer(config))
    first, second = _two_records_with_same_short_id()

    stored_first = storage.save(first)
    stored_second = storage.save(second)

    assert stored_first.location != stored_second.location
    assert len(list(tmp_path.glob("*.tseed"))) == 2


def test_directory_filenames_do_not_collide_on_uuid_prefix(tmp_path):
    config = TraceSeedConfig(output_directory=tmp_path)
    storage = DirectoryStorage(config, SafeSerializer(config))
    first, second = _two_records_with_same_short_id()

    stored_first = storage.save(first)
    stored_second = storage.save(second)

    assert stored_first.location != stored_second.location
    assert len([path for path in tmp_path.iterdir() if path.is_dir()]) == 2
