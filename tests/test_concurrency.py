"""Thread-safety: IDs únicos, contextos isolados por thread e async."""

import asyncio
import threading
import unittest

from traceseed import TraceSeedConfig, breadcrumb, capture_exception, context
from traceseed.context import current_breadcrumbs, current_context
from traceseed.storage.memory import MemoryStorage


def _make_memory_storage(cfg=None):
    cfg = cfg or TraceSeedConfig(re_raise=False)
    stor = MemoryStorage()
    return cfg, stor


class TestConcurrentCaptures(unittest.TestCase):
    def test_concurrent_captures_produce_unique_ids(self):
        cfg, stor = _make_memory_storage()
        results = []

        def worker():
            try:
                raise ValueError("concurrent error")
            except ValueError as exc:
                r = capture_exception(exc, config=cfg, storage=stor)
                if r:
                    results.append(r.record.incident_id)

        threads = [threading.Thread(target=worker) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(results), 20)
        self.assertEqual(len(set(results)), 20, "IDs de incidente não são únicos!")

    def test_thread_contexts_are_isolated(self):
        """Contextos de threads diferentes não se misturam."""
        values_seen = {}

        def worker(thread_id):
            with context(thread_id=thread_id):
                import time

                time.sleep(0.01)  # permite intercalamento
                values_seen[thread_id] = current_context().get("thread_id")

        threads = [threading.Thread(target=worker, args=(f"t{i}",)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        for thread_id, seen in values_seen.items():
            self.assertEqual(seen, thread_id, f"Contexto contaminado: {thread_id} viu {seen}")

    def test_thread_breadcrumbs_are_isolated(self):
        """Breadcrumbs de threads diferentes não se misturam."""
        crumbs_seen = {}

        def worker(thread_id):
            breadcrumb("test", f"msg from {thread_id}")
            import time

            time.sleep(0.01)
            crumbs_seen[thread_id] = [b.message for b in current_breadcrumbs()]

        threads = [threading.Thread(target=worker, args=(f"t{i}",)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        for thread_id, msgs in crumbs_seen.items():
            self.assertEqual(len(msgs), 1)
            self.assertIn(thread_id, msgs[0])

    def test_async_contexts_are_isolated(self):
        """Contextos de corrotinas diferentes não se misturam."""

        async def task(task_id):
            async with asyncio.timeout(5):
                pass
            with context(task_id=task_id):
                await asyncio.sleep(0)
                return current_context().get("task_id")

        async def main():
            results = await asyncio.gather(*[task(f"t{i}") for i in range(10)])
            return results

        results = asyncio.run(main())
        for i, result in enumerate(results):
            self.assertEqual(
                result, f"t{i}", f"Contexto async contaminado: esperado t{i}, viu {result}"
            )


if __name__ == "__main__":
    unittest.main()
