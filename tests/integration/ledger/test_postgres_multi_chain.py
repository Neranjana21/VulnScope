# ruff: noqa: E501
"""Independent chains do not contend or interleave; hot chain X does not starve chain Y (F6)."""
from __future__ import annotations

import asyncio
import statistics
import time
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from ledger_pg_support import admin_fetch

from vulnscope.ledger.postgres_backend import PostgresChainBackend
from vulnscope.ledger.verify import verify

pytestmark = pytest.mark.integration


async def test_eight_chains_by_eight_tasks_each_gapless(backend: PostgresChainBackend, ledger_db: Any) -> None:
    chains = [f"engagement:{uuid.uuid4()}" for _ in range(6)] + [f"intake:{uuid.uuid4()}" for _ in range(2)]

    async def writer(cid: str, w: int) -> None:
        for i in range(10):
            await backend.append(cid, "policy.decision", "system", {"w": w, "i": i}, datetime.now(UTC))

    await asyncio.gather(*(writer(c, w) for c in chains for w in range(8)))
    for cid in chains:
        rows = [e async for e in backend.read(cid)]
        assert [e.seq for e in rows] == list(range(80))
        assert all(e.chain_id == cid for e in rows)
        assert (await verify(cid, backend)).result == "ok"
    heads = admin_fetch(ledger_db, "SELECT chain_id, seq FROM chain_heads WHERE chain_id = ANY($1::text[])", chains)
    assert sorted((r["chain_id"], r["seq"]) for r in heads) == sorted((c, 79) for c in chains)
    first = {(await backend.head(c)).prev_hash for c in chains}  # type: ignore[union-attr]
    assert len(first) == len(chains)  # distinct record hashes, distinct chains


async def test_a_hot_chain_does_not_starve_another_chain(backend: PostgresChainBackend) -> None:
    hot, cold = f"engagement:{uuid.uuid4()}", f"engagement:{uuid.uuid4()}"
    latencies: list[float] = []

    async def hot_writer(w: int) -> None:
        for i in range(10):
            await backend.append(hot, "policy.decision", "system", {"w": w, "i": i}, datetime.now(UTC))

    async def cold_writer() -> None:
        for i in range(20):
            t0 = time.perf_counter()
            await backend.append(cold, "policy.decision", "system", {"i": i}, datetime.now(UTC))
            latencies.append(time.perf_counter() - t0)

    await asyncio.gather(cold_writer(), *(hot_writer(w) for w in range(40)))
    latencies.sort()
    p95 = latencies[int(len(latencies) * 0.95) - 1]
    print(f"cold-chain p50={statistics.median(latencies) * 1000:.0f}ms p95={p95 * 1000:.0f}ms")
    assert p95 < 2.0, "a hot chain starved another chain (per-chain gate, max 4 pool connections)"
