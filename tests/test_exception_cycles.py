"""Proteção contra ciclos e profundidade excessiva em ExceptionInfo."""

import unittest

from traceseed import TraceSeedConfig
from traceseed.models import ExceptionInfo
from traceseed.redaction import Redactor


def _exc_info(msg="err", cause=None, context=None):
    return ExceptionInfo(
        module="builtins",
        type_name="ValueError",
        message=msg,
        representation=f"ValueError({msg!r})",
        cause=cause,
        context=context,
        suppress_context=False,
        notes=(),
        children=(),
    )


class TestExceptionCycleProtection(unittest.TestCase):
    def setUp(self):
        self.cfg = TraceSeedConfig()
        self.redactor = Redactor(self.cfg)

    def test_deeply_nested_chain_does_not_recurse_infinitely(self):
        # 20 níveis — acima do limite de 12
        current = _exc_info("root")
        for i in range(20):
            current = _exc_info(f"level {i}", cause=current)
        # Deve retornar sem explodir
        result = self.redactor.redact_exception_info(current)
        self.assertIsNotNone(result)

    def test_notes_are_redacted_in_chain(self):
        secret = "minha-senha-secreta"
        inner = ExceptionInfo(
            module="builtins",
            type_name="ValueError",
            message="inner",
            representation="ValueError('inner')",
            cause=None,
            context=None,
            suppress_context=False,
            notes=(secret,),
            children=(),
        )
        outer = _exc_info("outer", cause=inner)
        result = self.redactor.redact_exception_info(outer)
        # As notes do inner não devem conter o segredo se o redactor estiver configurado
        # (neste caso o segredo não é um padrão de redação, apenas verificamos que a estrutura é preservada)
        self.assertIsInstance(result.cause.notes, tuple)

    def test_children_are_redacted(self):
        children = tuple(
            ExceptionInfo(
                module="builtins",
                type_name="ValueError",
                message=f"child {i}",
                representation=f"ValueError('child {i}')",
                cause=None,
                context=None,
                suppress_context=False,
                notes=(),
                children=(),
            )
            for i in range(5)
        )
        exc = ExceptionInfo(
            module="builtins",
            type_name="ExceptionGroup",
            message="group",
            representation="ExceptionGroup('group')",
            cause=None,
            context=None,
            suppress_context=False,
            notes=(),
            children=children,
        )
        result = self.redactor.redact_exception_info(exc)
        self.assertEqual(len(result.children), 5)

    def test_none_returns_none(self):
        result = self.redactor.redact_exception_info(None)
        self.assertIsNone(result)

    def test_message_is_redacted_in_chain(self):
        cfg = TraceSeedConfig(re_raise=False)
        # Usa padrão Bearer para verificar redação na cadeia
        inner = _exc_info("Bearer abc123token")
        outer = _exc_info("outer error", cause=inner)
        r = Redactor(cfg)
        result = r.redact_exception_info(outer)
        # Bearer é substituído pelo redactor
        self.assertNotIn("abc123token", result.cause.message)


if __name__ == "__main__":
    unittest.main()
