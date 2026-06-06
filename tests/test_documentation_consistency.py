"""Consistência da documentação: sem claims sobre unittest, run_tests.py ou install_local.py."""

from __future__ import annotations

import pathlib
import unittest

_ROOT = pathlib.Path(__file__).parent.parent
_DOCS_DIRS = [_ROOT, _ROOT / "docs"]
_DOC_EXTENSIONS = {".md", ".rst", ".txt"}


def _doc_files() -> list[pathlib.Path]:
    result = []
    for d in _DOCS_DIRS:
        if d.is_dir():
            for p in d.iterdir():
                if p.suffix in _DOC_EXTENSIONS and p.is_file():
                    result.append(p)
    return result


def _read(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8")


class TestNoObsoleteScripts(unittest.TestCase):
    def test_readme_does_not_mention_run_tests_py(self):
        readme = _ROOT / "README.md"
        if not readme.exists():
            self.skipTest("README.md não encontrado")
        self.assertNotIn("run_tests.py", _read(readme))

    def test_readme_does_not_mention_install_local_py(self):
        readme = _ROOT / "README.md"
        if not readme.exists():
            self.skipTest("README.md não encontrado")
        self.assertNotIn("install_local.py", _read(readme))

    def test_readme_does_not_mention_uninstall_local_py(self):
        readme = _ROOT / "README.md"
        if not readme.exists():
            self.skipTest("README.md não encontrado")
        self.assertNotIn("uninstall_local.py", _read(readme))

    def test_contributing_does_not_mention_run_tests_py(self):
        contributing = _ROOT / "CONTRIBUTING.md"
        if not contributing.exists():
            self.skipTest("CONTRIBUTING.md não encontrado")
        self.assertNotIn("run_tests.py", _read(contributing))

    def test_contributing_does_not_mention_install_local_py(self):
        contributing = _ROOT / "CONTRIBUTING.md"
        if not contributing.exists():
            self.skipTest("CONTRIBUTING.md não encontrado")
        self.assertNotIn("install_local.py", _read(contributing))


class TestDevToolsDocumented(unittest.TestCase):
    def test_readme_mentions_pytest(self):
        readme = _ROOT / "README.md"
        if not readme.exists():
            self.skipTest("README.md não encontrado")
        content = _read(readme).lower()
        self.assertIn("pytest", content)

    def test_readme_mentions_ruff(self):
        readme = _ROOT / "README.md"
        if not readme.exists():
            self.skipTest("README.md não encontrado")
        content = _read(readme).lower()
        self.assertIn("ruff", content)

    def test_readme_mentions_mypy(self):
        readme = _ROOT / "README.md"
        if not readme.exists():
            self.skipTest("README.md não encontrado")
        content = _read(readme).lower()
        self.assertIn("mypy", content)

    def test_contributing_mentions_pytest(self):
        contributing = _ROOT / "CONTRIBUTING.md"
        if not contributing.exists():
            self.skipTest("CONTRIBUTING.md não encontrado")
        content = _read(contributing).lower()
        self.assertIn("pytest", content)


class TestNoIncorrectRuntimeDependencyClaims(unittest.TestCase):
    def _all_doc_content(self) -> str:
        from contextlib import suppress

        parts = []
        for p in _doc_files():
            with suppress(Exception):
                parts.append(_read(p))
        return "\n".join(parts)

    def test_no_claim_of_stdlib_only_in_tests(self):
        """Docs não devem afirmar que stdlib é suficiente *nos testes* (pytest/ruff/mypy são dev deps)."""
        readme = _ROOT / "README.md"
        if not readme.exists():
            self.skipTest("README.md não encontrado")
        content = _read(readme)
        # O claim problemático era "a biblioteca padrão do Python é suficiente em runtime E nos testes"
        # A versão correta menciona somente runtime
        if "biblioteca padrão" in content and "nos testes" in content:
            # Garante que a afirmação inválida não apareça conjuntamente
            self.assertNotIn(
                "biblioteca padrão do Python é suficiente em runtime e nos testes",
                content,
            )

    def test_architecture_doc_corrected(self):
        arch = _ROOT / "docs" / "ARCHITECTURE.md"
        if not arch.exists():
            self.skipTest("docs/ARCHITECTURE.md não encontrado")
        content = _read(arch)
        # A afirmação incorreta original era "A biblioteca padrão do Python é suficiente em runtime e nos testes."
        self.assertNotIn(
            "é suficiente em runtime e nos testes",
            content,
        )


class TestNoUnittestOnlyClaims(unittest.TestCase):
    """Docs não devem afirmar que o projeto usa apenas unittest."""

    def test_readme_does_not_claim_unittest_only(self):
        readme = _ROOT / "README.md"
        if not readme.exists():
            self.skipTest("README.md não encontrado")
        content = _read(readme).lower()
        # Se mencionar unittest isoladamente como o runner de testes, é um erro
        # Mas pode mencionar unittest como parte do ecossistema ou em código de exemplo
        # Verificamos que não há afirmação de "testes com unittest" sem mencionar pytest
        if "unittest" in content and "pytest" not in content:
            self.fail("README menciona unittest mas não pytest — documentação incompleta")


if __name__ == "__main__":
    unittest.main()
