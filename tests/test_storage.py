import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from traceseed import MemoryStorage, TraceSeedConfig, capture_exception
from traceseed.errors import IntegrityError, InvalidPackageError, StorageError
from traceseed.serialization import SafeSerializer
from traceseed.storage import ArchiveStorage, DirectoryStorage


class StorageTests(unittest.TestCase):
    def capture_to(self, directory, *, storage_cls=ArchiveStorage):
        config = TraceSeedConfig(output_directory=directory)
        serializer = SafeSerializer(config)
        storage = storage_cls(config, serializer)
        try:
            raise ValueError("customer 123 not found")
        except ValueError as error:
            result = capture_exception(
                error, operation="load/customer", config=config, storage=storage, strict=True
            )
        return result, storage

    def test_archive_is_created_with_tseed_extension(self):
        with tempfile.TemporaryDirectory() as tmp:
            result, _ = self.capture_to(tmp)
            self.assertTrue(Path(result.location).is_file())
            self.assertEqual(Path(result.location).suffix, ".tseed")

    def test_archive_contains_expected_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            result, storage = self.capture_to(tmp)
            files = storage.load_files(result.location)
            expected = {
                "manifest.json",
                "summary.json",
                "record.json",
                "traceback.txt",
                "README.txt",
            }
            self.assertTrue(expected.issubset(files))

    def test_manifest_can_be_verified(self):
        with tempfile.TemporaryDirectory() as tmp:
            result, storage = self.capture_to(tmp)
            manifest = storage.verify(result.location)
            self.assertEqual(manifest["fingerprint"], result.record.fingerprint)

    def test_tampering_is_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            result, storage = self.capture_to(tmp)
            path = Path(result.location)
            # Lê todos os arquivos, modifica summary.json, re-escreve sem duplicatas
            files = {}
            with zipfile.ZipFile(path, "r") as archive:
                for name in archive.namelist():
                    files[name] = archive.read(name)
            files["summary.json"] = b"{}"
            with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                for name, content in files.items():
                    archive.writestr(name, content)
            with self.assertRaises(IntegrityError):
                storage.verify(path)

    def test_bad_zip_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.tseed"
            path.write_text("not zip")
            config = TraceSeedConfig(output_directory=tmp)
            storage = ArchiveStorage(config, SafeSerializer(config))
            with self.assertRaises(InvalidPackageError):
                storage.load_files(path)

    def test_missing_manifest_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.tseed"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("summary.json", "{}")
            config = TraceSeedConfig(output_directory=tmp)
            storage = ArchiveStorage(config, SafeSerializer(config))
            with self.assertRaises(InvalidPackageError):
                storage.verify(path)

    def test_path_traversal_member_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.tseed"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("../escape", "x")
            config = TraceSeedConfig(output_directory=tmp)
            storage = ArchiveStorage(config, SafeSerializer(config))
            with self.assertRaises(InvalidPackageError):
                storage.load_files(path)

    def test_filename_is_sanitized(self):
        with tempfile.TemporaryDirectory() as tmp:
            result, _ = self.capture_to(tmp)
            self.assertNotIn("/", Path(result.location).name)
            self.assertIn("load-customer", Path(result.location).name)

    def test_archive_is_deterministically_ordered(self):
        with tempfile.TemporaryDirectory() as tmp:
            result, _ = self.capture_to(tmp)
            with zipfile.ZipFile(result.location) as archive:
                self.assertEqual(archive.namelist(), sorted(archive.namelist()))

    def test_summary_is_plain_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            result, storage = self.capture_to(tmp)
            summary = json.loads(storage.load_files(result.location)["summary.json"])
            self.assertEqual(summary["exception"]["type_name"], "ValueError")

    def test_directory_storage_creates_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            result, storage = self.capture_to(tmp, storage_cls=DirectoryStorage)
            self.assertTrue(Path(result.location).is_dir())
            files = storage.load_files(result.location)
            self.assertIn("manifest.json", files)

    def test_directory_storage_rejects_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "file"
            path.write_text("x")
            config = TraceSeedConfig(output_directory=tmp)
            storage = DirectoryStorage(config, SafeSerializer(config))
            with self.assertRaises(InvalidPackageError):
                storage.load_files(path)

    def test_memory_storage(self):
        storage = MemoryStorage()
        try:
            raise RuntimeError("x")
        except RuntimeError as error:
            result = capture_exception(error, storage=storage)
        self.assertEqual(result.location.split(":")[0], "memory")
        self.assertEqual(storage.records[0].exception.type_name, "RuntimeError")

    def test_unwritable_output_raises_storage_error_in_strict_mode(self):
        config = TraceSeedConfig(output_directory=Path("/dev/null/child"))
        storage = ArchiveStorage(config, SafeSerializer(config))
        try:
            raise RuntimeError("x")
        except RuntimeError as error:
            with self.assertRaises(StorageError):
                capture_exception(error, config=config, storage=storage, strict=True)
