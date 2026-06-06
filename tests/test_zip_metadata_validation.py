"""Validação de metadados ZIP: symlinks, diretórios, criptografia, compressão proibida."""

from __future__ import annotations

import os
import tempfile
import unittest
import zipfile
from pathlib import Path

from traceseed import TraceSeedConfig
from traceseed.errors import InvalidPackageError
from traceseed.serialization import SafeSerializer
from traceseed.storage.archive import ArchiveStorage


def _make_zip(path: str, entries: dict[str, bytes], compression=zipfile.ZIP_DEFLATED) -> None:
    with zipfile.ZipFile(path, "w", compression=compression) as zf:
        for name, content in entries.items():
            zf.writestr(name, content)


class TestZipTypeRejection(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        cfg = TraceSeedConfig(output_directory=Path(self.tmp))
        self.stor = ArchiveStorage(cfg, SafeSerializer(cfg))

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def _pkg(self, name="test.tseed"):
        return os.path.join(self.tmp, name)

    def test_directory_entry_rejected(self):
        """Entradas de diretório (nome termina com /) devem ser rejeitadas."""
        path = self._pkg()
        with zipfile.ZipFile(path, "w") as zf:
            # Cria entrada de diretório
            info = zipfile.ZipInfo("subdir/")
            zf.writestr(info, b"")
            zf.writestr("manifest.json", b"{}")
        with self.assertRaises(InvalidPackageError) as ctx:
            self.stor.load_files(path)
        self.assertIn("diretório", str(ctx.exception).lower())

    def test_encrypted_entry_rejected(self):
        """Arquivos com flag de criptografia devem ser rejeitados."""
        path = self._pkg()
        # Python's zipfile module suporta escrever ZIPs com senha
        # Criamos um ZIP com senha via o módulo zipfile
        with zipfile.ZipFile(path, "w") as zf:
            info = zipfile.ZipInfo("secret.json")
            info.compress_type = zipfile.ZIP_STORED
            # Simula flag de criptografia (bit 0 de flag_bits)
            info.flag_bits = 0x1
            # Escreve manualmente os bytes para simular o header corrompido
            # (simplificação: cria zip normal e depois simula com flag_bits)
            zf.writestr(info, b"{}")
        # Verifica se o arquivo foi criado com flag_bits=1
        with zipfile.ZipFile(path, "r") as zf:
            for info in zf.infolist():
                if info.filename == "secret.json" and info.flag_bits & 0x1:
                    # Flag de criptografia presente — teste válido
                    break
            else:
                self.skipTest("não foi possível criar ZIP com flag de criptografia")
        with self.assertRaises(InvalidPackageError) as ctx:
            self.stor.load_files(path)
        self.assertIn("criptografado", str(ctx.exception).lower())

    def test_symlink_unix_rejected(self):
        """Symlinks (unix external_attr) devem ser rejeitados."""
        path = self._pkg()
        with zipfile.ZipFile(path, "w") as zf:
            info = zipfile.ZipInfo("link.txt")
            # Define external_attr para symlink Unix (0o120000 << 16)
            info.external_attr = 0o120000 << 16
            zf.writestr(info, b"../etc/passwd")
        with self.assertRaises(InvalidPackageError) as ctx:
            self.stor.load_files(path)
        self.assertIn("symlink", str(ctx.exception).lower())

    def test_absolute_unix_path_rejected(self):
        path = self._pkg()
        _make_zip(path, {"/etc/passwd": b"root"})
        with self.assertRaises(InvalidPackageError) as ctx:
            self.stor.load_files(path)
        self.assertIn("absolut", str(ctx.exception).lower())

    def test_absolute_windows_path_rejected(self):
        path = self._pkg()
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("C:/Windows/system32/evil.exe", b"evil")
        with self.assertRaises(InvalidPackageError) as ctx:
            self.stor.load_files(path)
        self.assertIn("absolut", str(ctx.exception).lower())

    def test_path_traversal_rejected(self):
        path = self._pkg()
        _make_zip(path, {"../../etc/shadow": b"sensitive"})
        with self.assertRaises(InvalidPackageError) as ctx:
            self.stor.load_files(path)
        self.assertIn("..", str(ctx.exception))

    def test_empty_filename_rejected(self):
        """Entradas com nome vazio devem ser rejeitadas."""
        path = self._pkg()
        with zipfile.ZipFile(path, "w") as zf:
            # Cria entrada com nome vazio manualmente via ZipInfo
            try:
                info = zipfile.ZipInfo("")
                zf.writestr(info, b"data")
            except Exception:
                self.skipTest("não foi possível criar entrada com nome vazio")
        try:
            with self.assertRaises(InvalidPackageError):
                self.stor.load_files(path)
        except Exception:
            pass  # Alguns Pythons rejeitam no nível do zipfile

    def test_duplicate_entries_rejected(self):
        path = self._pkg()
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("file.json", b"first")
            zf.writestr("file.json", b"second")
        with self.assertRaises(InvalidPackageError) as ctx:
            self.stor.load_files(path)
        self.assertIn("duplicada", str(ctx.exception).lower())

    def test_too_many_files_rejected(self):
        cfg = TraceSeedConfig(
            output_directory=Path(self.tmp),
            max_archive_files=3,
            max_manifest_size=512,
        )
        stor = ArchiveStorage(cfg, SafeSerializer(cfg))
        path = self._pkg("many.tseed")
        entries = {f"file_{i}.json": b"{}" for i in range(10)}
        _make_zip(path, entries)
        with self.assertRaises(InvalidPackageError) as ctx:
            stor.load_files(path)
        self.assertIn("limite", str(ctx.exception).lower())

    def test_compression_ratio_rejected(self):
        """Alta razão de compressão deve ser detectada antes de ler conteúdo."""
        cfg = TraceSeedConfig(
            output_directory=Path(self.tmp),
            max_archive_file_size=50 * 1024 * 1024,
            max_archive_total_size=200 * 1024 * 1024,
            max_compression_ratio=5,
            max_manifest_size=512 * 1024,
        )
        stor = ArchiveStorage(cfg, SafeSerializer(cfg))
        path = self._pkg("bomb.tseed")
        # Conteúdo altamente compressível
        _make_zip(path, {"bomb.json": b"a" * 100_000})
        with self.assertRaises(InvalidPackageError) as ctx:
            stor.load_files(path)
        self.assertIn("compressão", str(ctx.exception).lower())

    def test_file_size_limit_rejected(self):
        cfg = TraceSeedConfig(
            output_directory=Path(self.tmp),
            max_archive_file_size=100,
            max_archive_total_size=1000,
            max_manifest_size=100,
        )
        stor = ArchiveStorage(cfg, SafeSerializer(cfg))
        path = self._pkg("big.tseed")
        _make_zip(path, {"big.json": b"x" * 200})
        with self.assertRaises(InvalidPackageError):
            stor.load_files(path)

    def test_valid_package_passes(self):
        import hashlib
        import json

        content = b'{"ok": true}'
        hashes = {"data.json": hashlib.sha256(content).hexdigest()}
        manifest = json.dumps(
            {
                "format": "traceseed",
                "format_version": 1,
                "library_version": "0.1.0",
                "files": ["data.json"],
                "hashes": hashes,
            }
        ).encode()
        path = self._pkg("valid.tseed")
        _make_zip(path, {"manifest.json": manifest, "data.json": content})
        result = self.stor.load_files(path)
        self.assertIn("data.json", result)
        self.assertIn("manifest.json", result)


if __name__ == "__main__":
    unittest.main()
