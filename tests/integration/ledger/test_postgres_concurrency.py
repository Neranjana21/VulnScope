# ruff: noqa: E501
"""AC9, threaded variant: ONE ENGINE PER THREAD (each thread has its own event loop, pool and
connections), several writers on one chain. This models several API workers and proves the
serialization lives in the database, across separate pools. It deliberately does NOT share an
engine across threads (an asyncpg anti-pattern)."""
from __future__ import annotations

import asyncio
import threading
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from ledger_pg_support import open_backend

from vulnscope.ledger.verify import verify

pytestmark = pytest.mark.integration
THREADS, PER_THREAD = 8, 25


async def test_eight_threads_each_with_its_own_engine_one_chain(ledger_db: Any) -> None:
    cid = f"engagement:{uuid.uuid4()}"
    errors: list[BaseException] = []

    async def worker(w: int) -> None:
        engine, backend = await open_backend(ledger_db)
        try:
            for i in range(PER_THREAD):
                await backend.append(cid, "policy.decision", "system", {"w": w, "i": i}, datetime.now(UTC))
        finally:
            await engine.dispose()

    def run(w: int) -> None:
        try:
            asyncio.run(worker(w))
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=run, args=(w,)) for w in range(THREADS)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert errors == []

    engine, backend = await open_backend(ledger_db)
    try:
        rows = [e async for e in backend.read(cid)]
        total = THREADS * PER_THREAD
        assert [e.seq for e in rows] == list(range(total))
        res = await verify(cid, backend)
        assert (res.result, res.records) == ("ok", total)
    finally:
        await engine.dispose()
