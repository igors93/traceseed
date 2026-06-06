"""Verifica semântica de strict=True consistente em todos os 4 contextos de captura."""

import unittest

import traceseed
from traceseed import TraceSeedConfig, capture_exception, guard
from traceseed.errors import StorageError


def _broken_storage(cfg):
    """Storage que sempre lança OSError ao salvar."""

    class BrokenStorage:
        name = "broken"

        def save(self, record, extra=None):
            raise OSError("disco cheio")

    return BrokenStorage()


class TestStrictSemanticsCaptureException(unittest.TestCase):
    def _cfg(self):
        return TraceSeedConfig(re_raise=False)

    def test_strict_false_returns_none_on_storage_error(self):
        cfg = self._cfg()
        stor = _broken_storage(cfg)
        try:
            raise ValueError("test")
        except ValueError as exc:
            result = capture_exception(exc, config=cfg, storage=stor, strict=False)
        self.assertIsNone(result)

    def test_strict_true_raises_storage_error(self):
        cfg = self._cfg()
        stor = _broken_storage(cfg)
        with self.assertRaises(StorageError):
            try:
                raise ValueError("test")
            except ValueError as exc:
                capture_exception(exc, config=cfg, storage=stor, strict=True)

    def test_strict_true_original_exception_is_cause(self):
        cfg = self._cfg()
        stor = _broken_storage(cfg)
        try:
            try:
                raise ValueError("original")
            except ValueError as exc:
                capture_exception(exc, config=cfg, storage=stor, strict=True)
        except StorageError as se:
            self.assertIsInstance(se.__cause__, ValueError)
            self.assertEqual(str(se.__cause__), "original")


class TestStrictSemanticsDecorator(unittest.TestCase):
    def test_decorator_strict_false_does_not_hide_original(self):
        cfg = TraceSeedConfig(re_raise=True)
        stor = _broken_storage(cfg)

        @traceseed.capture(storage=stor, config=cfg, strict=False)
        def func():
            raise RuntimeError("from func")

        with self.assertRaises(RuntimeError):
            func()

    def test_decorator_strict_true_raises_storage_error(self):
        cfg = TraceSeedConfig(re_raise=False)
        stor = _broken_storage(cfg)

        @traceseed.capture(storage=stor, config=cfg, strict=True)
        def func():
            raise RuntimeError("from func")

        with self.assertRaises(StorageError):
            func()


class TestStrictSemanticsGuard(unittest.TestCase):
    def test_guard_strict_false_re_raises_original(self):
        cfg = TraceSeedConfig(re_raise=True)
        stor = _broken_storage(cfg)

        with self.assertRaises(RuntimeError), guard("op", storage=stor, config=cfg, strict=False):
            raise RuntimeError("guard original")

    def test_guard_strict_true_raises_storage_error(self):
        cfg = TraceSeedConfig(re_raise=False)
        stor = _broken_storage(cfg)

        with self.assertRaises(StorageError), guard("op", storage=stor, config=cfg, strict=True):
            raise RuntimeError("guard strict")


class TestStrictSemanticsAsync(unittest.TestCase):
    def test_async_decorator_strict_false(self):
        import asyncio

        cfg = TraceSeedConfig(re_raise=True)
        stor = _broken_storage(cfg)

        @traceseed.capture(storage=stor, config=cfg, strict=False)
        async def async_func():
            raise RuntimeError("async original")

        with self.assertRaises(RuntimeError):
            asyncio.run(async_func())

    def test_async_decorator_strict_true(self):
        import asyncio

        cfg = TraceSeedConfig(re_raise=False)
        stor = _broken_storage(cfg)

        @traceseed.capture(storage=stor, config=cfg, strict=True)
        async def async_func():
            raise RuntimeError("async strict")

        with self.assertRaises(StorageError):
            asyncio.run(async_func())


if __name__ == "__main__":
    unittest.main()
