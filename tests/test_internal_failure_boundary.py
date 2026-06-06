"""Fronteira global de falhas: componentes defeituosos não substituem a exceção original."""

from __future__ import annotations

import unittest
from typing import Any

from traceseed import TraceSeedConfig, capture_exception, guard
from traceseed.collectors import CollectorRegistry
from traceseed.engine import CaptureEngine
from traceseed.errors import CallbackError, StorageError
from traceseed.models import CaptureContext, CaptureResult
from traceseed.serialization import SafeSerializer
from traceseed.storage import MemoryStorage


class BrokenStorage:
    name = "broken"

    def save(self, record: Any, extra: Any = None) -> Any:
        raise OSError("storage failure")


class BrokenSerializer:
    def encode(self, value: Any) -> Any:
        raise ValueError("serializer failure")

    def register_codec(self, codec: Any) -> None:
        pass


class BrokenCollector:
    name = "broken_col"

    def collect(self, exc: Any, ctx: Any, config: Any) -> dict:
        raise RuntimeError("collector failure")


class BrokenRedactor:
    """Redactor que sempre lança."""

    def redact_exception_info(self, info: Any, *args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("redactor failure")

    def redact(self, value: Any, key: Any = None) -> Any:
        raise RuntimeError("redactor failure")

    def redact_breadcrumb(self, b: Any) -> Any:
        raise RuntimeError("redactor failure")

    def redact_text(self, text: Any) -> Any:
        raise RuntimeError("redactor failure")


class BrokenFingerprinter:
    def generate(self, *args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("fingerprinter failure")


class TestInternalFailureBoundary(unittest.TestCase):
    def _config(self) -> TraceSeedConfig:
        return TraceSeedConfig(re_raise=False)

    def test_broken_storage_strict_false_does_not_raise(self):
        """strict=False: storage failure não propaga exceção."""
        result = capture_exception(
            ValueError("original"),
            storage=BrokenStorage(),
            strict=False,
        )
        self.assertIsNone(result)

    def test_broken_storage_strict_true_raises_storage_error(self):
        """strict=True: storage failure levanta StorageError com original como __cause__."""
        original = ValueError("original")
        with self.assertRaises(StorageError) as ctx:
            capture_exception(original, storage=BrokenStorage(), strict=True)
        self.assertIs(ctx.exception.__cause__, original)

    def test_broken_collector_strict_false_does_not_raise(self):
        """Coletor defeituoso com strict=False não propaga."""
        registry = CollectorRegistry()
        registry.register(BrokenCollector())
        cfg = self._config()
        ser = SafeSerializer(cfg)
        engine = CaptureEngine(cfg, registry, MemoryStorage(), ser)
        ctx = CaptureContext()
        result = engine.capture(ValueError("original"), ctx)
        self.assertIsNone(result.capture_error)
        self.assertEqual(len(result.record.collector_errors), 1)

    def test_redactor_failure_contained_by_global_boundary(self):
        """Se o redactor lança, a fronteira global contém o erro."""
        cfg = self._config()
        ser = SafeSerializer(cfg)
        engine = CaptureEngine(cfg, CollectorRegistry(), MemoryStorage(), ser)
        engine._redactor = BrokenRedactor()  # type: ignore[assignment]
        ctx = CaptureContext()
        result = engine.capture(ValueError("original"), ctx)
        # capture_error deve ser setado, mas a exceção não deve propagar
        self.assertIsNotNone(result.capture_error)
        self.assertIn("internal error", result.capture_error.lower())

    def test_fingerprinter_failure_contained_by_global_boundary(self):
        cfg = self._config()
        ser = SafeSerializer(cfg)
        engine = CaptureEngine(cfg, CollectorRegistry(), MemoryStorage(), ser)
        engine._fingerprinter = BrokenFingerprinter()  # type: ignore[assignment]
        ctx = CaptureContext()
        result = engine.capture(ValueError("original"), ctx)
        self.assertIsNotNone(result.capture_error)

    def test_callback_failure_strict_false_does_not_propagate(self):
        def bad_callback(result: CaptureResult) -> None:
            raise RuntimeError("callback failure")

        result = capture_exception(
            ValueError("original"),
            storage=MemoryStorage(),
            on_captured=bad_callback,
            strict=False,
        )
        self.assertIsNotNone(result)

    def test_callback_failure_strict_true_raises_callback_error(self):
        original = ValueError("original")

        def bad_callback(result: CaptureResult) -> None:
            raise RuntimeError("callback failure")

        with self.assertRaises(CallbackError) as ctx:
            capture_exception(
                original,
                storage=MemoryStorage(),
                on_captured=bad_callback,
                strict=True,
            )
        self.assertIs(ctx.exception.__cause__, original)

    def test_guard_with_broken_storage_strict_false(self):
        """guard com storage defeituoso não propaga em strict=False."""
        cfg = TraceSeedConfig(re_raise=True)
        with (
            self.assertRaises(RuntimeError),
            guard("op", storage=BrokenStorage(), config=cfg, strict=False),
        ):
            raise RuntimeError("original")

    def test_capture_exception_does_not_replace_original(self):
        """Em strict=False, exceção interna nunca substitui a original."""
        cfg = self._config()
        original = ValueError("the original exception")
        result = capture_exception(original, storage=BrokenStorage(), config=cfg, strict=False)
        self.assertIsNone(result)

    def test_object_with_broken_repr_is_captured(self):
        """Objeto com repr() defeituoso não impede captura."""

        class BadRepr:
            def __repr__(self):
                raise RuntimeError("repr failed")

        original = ValueError("test")
        original.bad_obj = BadRepr()  # type: ignore[attr-defined]
        storage = MemoryStorage()
        result = capture_exception(original, storage=storage, metadata={"obj": BadRepr()})
        self.assertIsNotNone(result)


class TestStrictSemantics(unittest.TestCase):
    def test_strict_true_guard_with_broken_storage(self):
        cfg = TraceSeedConfig(re_raise=False)
        with (
            self.assertRaises(StorageError),
            guard("op", storage=BrokenStorage(), config=cfg, strict=True),
        ):
            raise ValueError("original")

    def test_strict_false_prints_to_stderr(self):
        import io
        from contextlib import redirect_stderr

        err = io.StringIO()
        with redirect_stderr(err):
            result = capture_exception(
                ValueError("test"),
                storage=BrokenStorage(),
                strict=False,
            )
        self.assertIsNone(result)
        self.assertIn("traceseed:", err.getvalue())


if __name__ == "__main__":
    unittest.main()
