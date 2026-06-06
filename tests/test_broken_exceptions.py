"""Exceções defeituosas: str() e repr() que lançam, notas inválidas, ciclos reais."""

from __future__ import annotations

import unittest

from traceseed.collectors import build_exception_info
from traceseed.models import ExceptionInfo


class BrokenStr(Exception):
    def __str__(self):
        raise RuntimeError("str() failed intentionally")


class BrokenRepr(Exception):
    def __repr__(self):
        raise RuntimeError("repr() failed intentionally")


class BrokenStrAndRepr(Exception):
    def __str__(self):
        raise ValueError("str broken")

    def __repr__(self):
        raise ValueError("repr broken")


class TestBrokenExceptions(unittest.TestCase):
    def test_broken_str_does_not_propagate(self):
        """build_exception_info não deve propagar exceção de __str__."""
        exc = BrokenStr("test")
        result = build_exception_info(exc)
        self.assertIsInstance(result, ExceptionInfo)
        self.assertIn("str()", result.message)

    def test_broken_repr_does_not_propagate(self):
        exc = BrokenRepr("test")
        result = build_exception_info(exc)
        self.assertIsInstance(result, ExceptionInfo)
        self.assertIn("repr()", result.representation)

    def test_both_broken_does_not_propagate(self):
        exc = BrokenStrAndRepr("test")
        result = build_exception_info(exc)
        self.assertIsInstance(result, ExceptionInfo)
        self.assertIn("raised", result.message.lower())
        self.assertIn("raised", result.representation.lower())

    def test_direct_self_cause_cycle_does_not_recurse(self):
        """exc.__cause__ = exc não deve causar recursão infinita."""
        exc = RuntimeError("cycle")
        exc.__cause__ = exc  # type: ignore[assignment]
        result = build_exception_info(exc)
        self.assertIsInstance(result, ExceptionInfo)
        # O __cause__ deve ser tratado como limite de ciclo
        if result.cause is not None:
            self.assertIn("DEPTH_OR_CYCLE_LIMIT", result.cause.message)

    def test_indirect_cause_cycle_does_not_recurse(self):
        """A → B → A não deve causar recursão."""
        a = RuntimeError("a")
        b = RuntimeError("b")
        a.__cause__ = b  # type: ignore[assignment]
        b.__cause__ = a  # type: ignore[assignment]
        result = build_exception_info(a)
        self.assertIsInstance(result, ExceptionInfo)

    def test_context_cycle_does_not_recurse(self):
        """Ciclo via __context__ também é protegido."""
        a = RuntimeError("a")
        b = RuntimeError("b")
        a.__context__ = b  # type: ignore[assignment]
        b.__context__ = a  # type: ignore[assignment]
        result = build_exception_info(a)
        self.assertIsInstance(result, ExceptionInfo)

    def test_extremely_deep_chain_does_not_overflow(self):
        """Cadeia de 100 exceções não causa RecursionError."""
        root = RuntimeError("root")
        current = root
        for i in range(100):
            exc = RuntimeError(f"level {i}")
            exc.__cause__ = current  # type: ignore[assignment]
            current = exc
        result = build_exception_info(current)
        self.assertIsInstance(result, ExceptionInfo)

    def test_non_string_notes_are_handled(self):
        """Notas que não são strings devem ser convertidas com repr()."""
        exc = ValueError("with notes")
        exc.add_note("string note")
        exc.__notes__.append(42)  # type: ignore[attr-defined]
        exc.__notes__.append(None)  # type: ignore[attr-defined]
        result = build_exception_info(exc)
        self.assertIsInstance(result.notes, tuple)
        self.assertEqual(result.notes[0], "string note")
        self.assertIn("42", result.notes[1])
        self.assertIn("None", result.notes[2])

    def test_exception_group_children_limited(self):
        """ExceptionGroup com muitos filhos deve ser limitado."""
        children = [ValueError(f"child {i}") for i in range(100)]
        exc_group = ExceptionGroup("many", children)  # type: ignore[name-defined]
        result = build_exception_info(exc_group, max_children=5)
        self.assertIsInstance(result, ExceptionInfo)

    def test_depth_limit_returns_sentinel(self):
        """Ao atingir max_depth, retorna ExceptionInfo com mensagem de limite."""
        exc = RuntimeError("root")
        result = build_exception_info(exc, _depth=25, max_depth=20)
        self.assertIsInstance(result, ExceptionInfo)
        self.assertIn("DEPTH_OR_CYCLE_LIMIT", result.message)

    def test_full_capture_works_with_broken_exception(self):
        """capture_exception deve ser robusto com exceções defeituosas."""
        from traceseed import capture_exception
        from traceseed.storage import MemoryStorage

        storage = MemoryStorage()
        exc = BrokenStr("test")
        result = capture_exception(exc, storage=storage)
        self.assertIsNotNone(result)
        self.assertEqual(len(storage.records), 1)


if __name__ == "__main__":
    unittest.main()
