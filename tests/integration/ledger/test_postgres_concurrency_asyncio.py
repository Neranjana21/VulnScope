# ruff: noqa: E501
"""AC9 / SEC-7: many asyncio writers on ONE engine and ONE chain stay linear with no gaps."""
from __future__ import annotations

import asyncio
import time
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest

from vulnscope.ledger.postgres_backend import PostgresChainBackend
from vulnscope.ledger.verify import verify

pytestmark = pytest.mark.integration
TASKS, PER_TASK = 32, 40


async def test_32_tasks_by_40_appends_on_one_chain(backend: PostgresChainBackend, capsys: Any) -> None:
    cid = f"engagement:{uuid.uuid4()}"

    async def writer(w: int) -> None:
        for i in range(PER_TASK):
            await backend.append(cid, "policy.decision", "system", {"w": w, "i": i}, datetime.now(UTC))

    t0 = time.perf_counter()
    results = await asyncio.gather(*(writer(w) for w in range(TASKS)), return_exceptions=True)
    elapsed = time.perf_counter() - t0
    assert [r for r in results if isinstance(r, BaseException)] == []  # no IntegrityError, no timeout

    rows = [e async for e in backend.read(cid)]
    total = TASKS * PER_TASK
    assert [e.seq for e in rows] == list(range(total))
    assert all(rows[i].prev_hash == rows[i - 1].record_hash for i in range(1, total))
    res = await verify(cid, backend)
    assert (res.result, res.records) == ("ok", total)
    with capsys.disabled():
        print(f"\npg asyncio: {total} appends, {TASKS} tasks, {elapsed:.2f}s = {total / elapsed:.0f} rec/s")
