import asyncio
import unittest

from traceseed.config import TraceSeedConfig, configure, reset_config
from traceseed.context import (
    breadcrumb,
    clear_context,
    context,
    current_breadcrumbs,
    current_context,
    reset_context,
    set_context,
)


class ContextTests(unittest.TestCase):
    def setUp(self):
        clear_context()
        reset_config()

    def tearDown(self):
        clear_context()
        reset_config()

    def test_context_adds_values(self):
        with context(request_id="abc"):
            self.assertEqual(current_context()["request_id"], "abc")

    def test_context_restores_previous_values(self):
        with context(user=1):
            with context(user=2, tenant="a"):
                self.assertEqual(current_context(), {"user": 2, "tenant": "a"})
            self.assertEqual(current_context(), {"user": 1})
        self.assertEqual(current_context(), {})

    def test_current_context_is_copy(self):
        with context(value=1):
            snapshot = current_context()
            snapshot["value"] = 99
            self.assertEqual(current_context()["value"], 1)

    def test_set_and_reset_context(self):
        token = set_context("x", 10)
        self.assertEqual(current_context()["x"], 10)
        reset_context(token)
        self.assertNotIn("x", current_context())

    def test_set_context_rejects_empty_key(self):
        with self.assertRaises(ValueError):
            set_context("", 1)

    def test_breadcrumb_creation(self):
        item = breadcrumb("db", "loaded", row=3)
        self.assertEqual(item.category, "db")
        self.assertEqual(current_breadcrumbs()[0].data["row"], 3)

    def test_breadcrumb_rejects_empty_category(self):
        with self.assertRaises(ValueError):
            breadcrumb("", "message")

    def test_breadcrumb_rejects_empty_message(self):
        with self.assertRaises(ValueError):
            breadcrumb("x", " ")

    def test_breadcrumb_limit(self):
        configure(TraceSeedConfig(max_breadcrumbs=2))
        breadcrumb("a", "1")
        breadcrumb("a", "2")
        breadcrumb("a", "3")
        self.assertEqual([item.message for item in current_breadcrumbs()], ["2", "3"])

    def test_clear_context_clears_both(self):
        set_context("x", 1)
        breadcrumb("a", "b")
        clear_context()
        self.assertEqual(current_context(), {})
        self.assertEqual(current_breadcrumbs(), ())

    def test_contextvars_are_isolated_between_async_tasks(self):
        async def worker(value):
            with context(worker=value):
                await asyncio.sleep(0)
                return current_context()["worker"]

        async def run():
            return await asyncio.gather(worker("a"), worker("b"))

        self.assertEqual(asyncio.run(run()), ["a", "b"])
