"""Garante que segredos não aparecem em nenhuma parte do pacote .tseed salvo."""

import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from traceseed import TraceSeedConfig, capture_exception
from traceseed.serialization import SafeSerializer
from traceseed.storage.archive import ArchiveStorage

# Segredos com cobertura pelos padrões de redação padrão
BEARER = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig"
CARD = "4532 1234 5678 9012"
# Campo sensível por nome — redactado via redact_fields
FIELD_SECRET = "campo-secreto-12345"


def _capture_to_tempdir(exc, metadata=None):
    with tempfile.TemporaryDirectory() as tmp:
        cfg = TraceSeedConfig(
            output_directory=Path(tmp),
            re_raise=False,
        )
        ser = SafeSerializer(cfg)
        stor = ArchiveStorage(cfg, ser)
        result = capture_exception(exc, config=cfg, storage=stor, metadata=metadata or {})
        assert result is not None, "Captura falhou inesperadamente"
        pkg = Path(result.location)
        with zipfile.ZipFile(pkg, "r") as zf:
            return {name: zf.read(name) for name in zf.namelist()}


class TestSecretNotInPackage(unittest.TestCase):
    def test_password_field_in_metadata_is_redacted(self):
        """Campos 'password'/'token' em metadata são redactados pelo nome."""
        try:
            raise ValueError("operação falhou")
        except ValueError as exc:
            files = _capture_to_tempdir(
                exc, metadata={"password": FIELD_SECRET, "token": "tok-abc"}
            )
        all_text = b"\n".join(files.values()).decode("utf-8", errors="replace")
        self.assertNotIn(
            FIELD_SECRET, all_text, "Segredo do campo 'password' encontrado no pacote!"
        )
        self.assertNotIn("tok-abc", all_text, "Token encontrado no pacote!")

    def test_bearer_token_in_exception_message_is_redacted(self):
        """Bearer tokens no texto da exceção são redactados pelo padrão padrão."""
        try:
            raise RuntimeError(f"falha ao autenticar: {BEARER}")
        except RuntimeError as exc:
            files = _capture_to_tempdir(exc)
        all_text = b"\n".join(files.values()).decode("utf-8", errors="replace")
        # O prefixo "eyJhbGci" é parte do token e deve desaparecer
        self.assertNotIn("eyJhbGci", all_text, "Token JWT encontrado no pacote!")

    def test_credit_card_in_exception_message_is_redacted(self):
        """Números de cartão no texto da exceção são redactados pelo padrão padrão."""
        try:
            raise RuntimeError(f"processando cartão {CARD}")
        except RuntimeError as exc:
            files = _capture_to_tempdir(exc)
        all_text = b"\n".join(files.values()).decode("utf-8", errors="replace")
        self.assertNotIn(CARD, all_text, "Número de cartão encontrado no pacote!")

    def test_bearer_in_traceback_text_is_redacted(self):
        """Bearer token no traceback.txt é redactado."""
        try:
            raise ValueError(f"token: {BEARER}")
        except ValueError as exc:
            files = _capture_to_tempdir(exc)
        tb_text = files.get("traceback.txt", b"").decode("utf-8", errors="replace")
        self.assertNotIn("eyJhbGci", tb_text, "Token JWT encontrado no traceback.txt!")

    def test_fingerprint_canonical_is_sanitized(self):
        """O canonical da fingerprint não deve conter tokens."""
        try:
            raise ValueError(f"token: {BEARER}")
        except ValueError as exc:
            files = _capture_to_tempdir(exc)
        canonical_raw = files.get("fingerprint-canonical.json", b"")
        if canonical_raw:
            canonical = json.loads(canonical_raw)
            text = json.dumps(canonical)
            self.assertNotIn("eyJhbGci", text, "Token encontrado no fingerprint canonical!")

    def test_bearer_in_nested_exception_is_redacted(self):
        """Bearer token em exceção aninhada é redactado na cadeia completa."""
        try:
            try:
                raise ValueError(f"auth error: {BEARER}")
            except ValueError as cause:
                raise RuntimeError("operação falhou") from cause
        except RuntimeError as exc:
            files = _capture_to_tempdir(exc)
        all_text = b"\n".join(files.values()).decode("utf-8", errors="replace")
        self.assertNotIn("eyJhbGci", all_text, "Token JWT encontrado em exceção aninhada!")

    def test_api_key_field_in_metadata_is_redacted(self):
        """Campo api_key em metadata é redactado pelo nome."""
        try:
            raise RuntimeError("api failed")
        except RuntimeError as exc:
            files = _capture_to_tempdir(exc, metadata={"api_key": "sk-very-secret-key"})
        all_text = b"\n".join(files.values()).decode("utf-8", errors="replace")
        self.assertNotIn("sk-very-secret-key", all_text, "api_key encontrada no pacote!")


if __name__ == "__main__":
    unittest.main()
