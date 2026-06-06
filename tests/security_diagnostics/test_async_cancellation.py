from __future__ import annotations

import asyncio

import pytest

from traceseed import MemoryStorage, TraceSeedConfig, capture, guard


def test_decorated_coroutine_never_suppresses_cancellation():
    storage = MemoryStorage()
    config = TraceSeedConfig(re_raise=False)

    @capture(storage=storage, config=config)
    async def cancelled_operation():
        raise asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(cancelled_operation())
    assert storage.records == []


def test_guard_never_suppresses_cancellation_inside_async_task():
    storage = MemoryStorage()
    config = TraceSeedConfig(re_raise=False)

    async def cancelled_operation():
        with guard("cancelled-operation", storage=storage, config=config):
            raise asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(cancelled_operation())
    assert storage.records == []


def test_task_group_cancellation_semantics_are_preserved():
    storage = MemoryStorage()
    config = TraceSeedConfig(re_raise=False)
    cancellation_seen = asyncio.Event()

    @capture(storage=storage, config=config)
    async def worker():
        try:
            await asyncio.sleep(60)
        finally:
            cancellation_seen.set()

    async def run_group():
        task = asyncio.create_task(worker())
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(run_group())
    assert cancellation_seen.is_set()
    assert storage.records == []
