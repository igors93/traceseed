"""Idempotência dos hooks asyncio: WeakKeyDictionary, loops independentes."""

from __future__ import annotations

import asyncio
import unittest

from traceseed.api import install_asyncio, uninstall_asyncio


class TestAsyncioHookIdempotency(unittest.TestCase):
    def _new_loop(self) -> asyncio.AbstractEventLoop:
        return asyncio.new_event_loop()

    def test_double_install_returns_same_loop(self):
        """Instalar duas vezes no mesmo loop é idempotente."""
        lp = self._new_loop()
        try:
            r1 = install_asyncio(loop=lp)
            r2 = install_asyncio(loop=lp)
            self.assertIs(r1, lp)
            self.assertIs(r2, lp)
        finally:
            uninstall_asyncio(loop=lp)
            lp.close()

    def test_double_install_does_not_stack_handlers(self):
        """Dois install_asyncio não devem acumular handlers."""
        lp = self._new_loop()
        try:
            install_asyncio(loop=lp)
            handler_after_first = lp.get_exception_handler()
            install_asyncio(loop=lp)
            handler_after_second = lp.get_exception_handler()
            # Mesmo handler — não foi substituído
            self.assertIs(handler_after_first, handler_after_second)
        finally:
            uninstall_asyncio(loop=lp)
            lp.close()

    def test_double_uninstall_is_safe(self):
        """Desinstalar duas vezes não lança exceção."""
        lp = self._new_loop()
        try:
            install_asyncio(loop=lp)
            uninstall_asyncio(loop=lp)
            uninstall_asyncio(loop=lp)  # segunda chamada não deve lançar
        finally:
            from contextlib import suppress

            with suppress(Exception):
                lp.close()

    def test_uninstall_without_install_is_safe(self):
        """uninstall_asyncio sem install prévio não lança exceção."""
        lp = self._new_loop()
        try:
            uninstall_asyncio(loop=lp)
        finally:
            lp.close()

    def test_two_independent_loops_get_independent_handlers(self):
        """Dois loops distintos têm handlers independentes."""
        lp1 = self._new_loop()
        lp2 = self._new_loop()
        try:
            install_asyncio(loop=lp1)
            install_asyncio(loop=lp2)

            h1 = lp1.get_exception_handler()
            h2 = lp2.get_exception_handler()

            # Handlers devem ser diferentes objetos (funções locais distintas)
            self.assertIsNotNone(h1)
            self.assertIsNotNone(h2)
            self.assertIsNot(h1, h2)
        finally:
            uninstall_asyncio(loop=lp1)
            uninstall_asyncio(loop=lp2)
            lp1.close()
            lp2.close()

    def test_install_restores_previous_handler_on_uninstall(self):
        """uninstall_asyncio deve restaurar o handler que existia antes do install."""
        lp = self._new_loop()

        def my_handler(lp2: asyncio.AbstractEventLoop, context: dict) -> None:
            pass

        lp.set_exception_handler(my_handler)
        try:
            install_asyncio(loop=lp)
            uninstall_asyncio(loop=lp)
            restored = lp.get_exception_handler()
            self.assertIs(restored, my_handler)
        finally:
            lp.close()

    def test_install_with_no_previous_handler_restores_none(self):
        """Se não havia handler antes do install, uninstall restaura None."""
        lp = self._new_loop()
        try:
            lp.set_exception_handler(None)
            install_asyncio(loop=lp)
            uninstall_asyncio(loop=lp)
            restored = lp.get_exception_handler()
            self.assertIsNone(restored)
        finally:
            lp.close()

    def test_handler_survives_gc_of_loop_reference(self):
        """WeakKeyDictionary: quando o loop é coletado, não há vazamento."""
        import gc
        import weakref

        lp = self._new_loop()
        ref = weakref.ref(lp)
        install_asyncio(loop=lp)
        del lp
        gc.collect()
        # Loop coletado — weakref deve ser None
        self.assertIsNone(ref())

    def test_install_returns_loop(self):
        lp = self._new_loop()
        try:
            returned = install_asyncio(loop=lp)
            self.assertIs(returned, lp)
        finally:
            uninstall_asyncio(loop=lp)
            lp.close()

    def test_handler_set_after_install(self):
        """Após install_asyncio, o loop deve ter um handler não-None."""
        lp = self._new_loop()
        try:
            lp.set_exception_handler(None)
            install_asyncio(loop=lp)
            self.assertIsNotNone(lp.get_exception_handler())
        finally:
            uninstall_asyncio(loop=lp)
            lp.close()


if __name__ == "__main__":
    unittest.main()
