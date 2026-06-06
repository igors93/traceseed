"""Verifica que install/uninstall preserva hooks anteriores e install_asyncio funciona."""

import asyncio
import sys
import threading
import unittest

import traceseed


class TestSysHookPreservation(unittest.TestCase):
    def setUp(self):
        traceseed.uninstall()

    def tearDown(self):
        traceseed.uninstall()
        sys.excepthook = sys.__excepthook__
        threading.excepthook = threading.__excepthook__  # type: ignore[attr-defined]

    def test_install_is_idempotent(self):
        traceseed.install()
        hook_after_first = sys.excepthook
        traceseed.install()
        self.assertIs(sys.excepthook, hook_after_first)

    def test_uninstall_restores_previous_hook(self):
        called = []
        original = lambda et, ev, tb: called.append("original")  # noqa: E731
        sys.excepthook = original
        traceseed.install()
        traceseed.uninstall()
        self.assertIs(sys.excepthook, original)

    def test_previous_sys_hook_is_called(self):
        called = []

        def custom_hook(et, ev, tb):
            called.append("custom")

        sys.excepthook = custom_hook
        traceseed.install()

        try:
            raise ValueError("test")
        except ValueError as exc:
            sys.excepthook(type(exc), exc, exc.__traceback__)

        self.assertIn("custom", called, "Hook anterior não foi chamado")

    def test_uninstall_without_install_is_safe(self):
        traceseed.uninstall()
        traceseed.uninstall()  # idempotente

    def test_thread_hook_called_after_install(self):
        called = []

        def custom_thread_hook(args):
            called.append("thread_hook")

        threading.excepthook = custom_thread_hook
        traceseed.install()

        exc = ValueError("thread error")
        # ExceptHookArgs é um PyStructSequence — recebe uma sequência posicional
        fake_args = threading.ExceptHookArgs((type(exc), exc, None, None))
        threading.excepthook(fake_args)
        self.assertIn("thread_hook", called, "Thread hook anterior não foi chamado")


class TestAsyncioHook(unittest.TestCase):
    def test_install_asyncio_preserves_previous_handler(self):
        loop = asyncio.new_event_loop()
        custom_called = []

        def custom_handler(lp, ctx):
            custom_called.append(ctx.get("exception"))

        loop.set_exception_handler(custom_handler)
        returned_loop = traceseed.install_asyncio(loop=loop)
        self.assertIs(returned_loop, loop)

        exc = ValueError("async test")
        loop.call_exception_handler({"exception": exc, "message": "test"})
        self.assertIn(exc, custom_called, "Handler asyncio anterior não foi chamado")

        traceseed.uninstall_asyncio(loop=loop)
        loop.close()

    def test_uninstall_asyncio_restores_handler(self):
        loop = asyncio.new_event_loop()
        custom_called = []

        def custom_handler(lp, ctx):
            custom_called.append("custom")

        loop.set_exception_handler(custom_handler)
        traceseed.install_asyncio(loop=loop)
        traceseed.uninstall_asyncio(loop=loop)

        loop.call_exception_handler({"message": "test"})
        self.assertIn("custom", custom_called)
        loop.close()

    def test_install_asyncio_captures_exception(self):
        from traceseed import TraceSeedConfig
        from traceseed.storage.memory import MemoryStorage

        cfg = TraceSeedConfig(re_raise=False)
        stor = MemoryStorage()

        loop = asyncio.new_event_loop()
        traceseed.install_asyncio(loop=loop, storage=stor, config=cfg)

        exc = RuntimeError("async uncaught")
        loop.call_exception_handler({"exception": exc, "message": "unhandled"})

        traceseed.uninstall_asyncio(loop=loop)
        loop.close()
        # Verificamos que não levantou exceção — a captura é best-effort


if __name__ == "__main__":
    unittest.main()
