"""Garante escrita atômica (temp file + os.replace) e limpeza em caso de erro."""

import os
import tempfile
import unittest
import zipfile
from pathlib import Path

from traceseed import TraceSeedConfig, capture_exception
from traceseed.serialization import SafeSerializer
from traceseed.storage.archive import ArchiveStorage


class TestAtomicStorage(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.cfg = TraceSeedConfig(
            output_directory=Path(self.tmp),
            re_raise=False,
        )
        self.ser = SafeSerializer(self.cfg)
        self.stor = ArchiveStorage(self.cfg, self.ser)

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_no_temp_files_left_after_success(self):
        try:
            raise ValueError("test atomic")
        except ValueError as exc:
            result = capture_exception(exc, config=self.cfg, storage=self.stor)

        self.assertIsNotNone(result)
        files = os.listdir(self.tmp)
        temp_files = [f for f in files if f.startswith(".traceseed-") and f.endswith(".tmp")]
        self.assertEqual(temp_files, [], f"Arquivos temporários encontrados: {temp_files}")

    def test_saved_file_is_valid_zip(self):
        try:
            raise TypeError("zip test")
        except TypeError as exc:
            result = capture_exception(exc, config=self.cfg, storage=self.stor)

        self.assertIsNotNone(result)
        self.assertTrue(zipfile.is_zipfile(result.location))

    def test_saved_file_has_tseed_extension(self):
        try:
            raise RuntimeError("extension test")
        except RuntimeError as exc:
            result = capture_exception(exc, config=self.cfg, storage=self.stor)

        self.assertIsNotNone(result)
        self.assertTrue(result.location.endswith(".tseed"))

    def test_no_temp_files_left_after_storage_error(self):
        """Mesmo com erro no save, não deve sobrar arquivos .tmp."""

        class FailAfterTempStorage(ArchiveStorage):
            def save(self, record, extra=None):
                # Força um erro depois de criar o temp file
                raise OSError("simulated disk full")

        fail_stor = FailAfterTempStorage(self.cfg, self.ser)
        try:
            raise ValueError("will fail")
        except ValueError as exc:
            result = capture_exception(exc, config=self.cfg, storage=fail_stor, strict=False)

        self.assertIsNone(result)
        files = os.listdir(self.tmp)
        temp_files = [f for f in files if f.startswith(".traceseed-") and f.endswith(".tmp")]
        self.assertEqual(temp_files, [], f"Arquivos temporários encontrados: {temp_files}")

    def test_multiple_captures_produce_distinct_files(self):
        for i in range(3):
            try:
                raise ValueError(f"error {i}")
            except ValueError as exc:
                result = capture_exception(exc, config=self.cfg, storage=self.stor)
            self.assertIsNotNone(result)

        tseed_files = [f for f in os.listdir(self.tmp) if f.endswith(".tseed")]
        self.assertEqual(len(tseed_files), 3)


if __name__ == "__main__":
    unittest.main()
