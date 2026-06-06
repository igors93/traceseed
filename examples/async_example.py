import asyncio

from traceseed import MemoryStorage, breadcrumb, capture, context

storage = MemoryStorage()


@capture(operation="async-job", storage=storage)
async def execute_job(job_id: int) -> None:
    breadcrumb("job", "job started", job_id=job_id)
    await asyncio.sleep(0)
    raise RuntimeError(f"job {job_id} failed")


async def main() -> None:
    with context(request_id="req-123"):
        try:
            await execute_job(42)
        except RuntimeError:
            record = storage.records[0]
            print(record.fingerprint)
            print(record.metadata)
            print(record.breadcrumbs)


if __name__ == "__main__":
    asyncio.run(main())
