# ruff: noqa: E501
"""First append to a brand-new chain: 16 writers released together, 20 rounds. Exactly one
``chain_heads`` row per chain, seqs 0..15, no unique violation (READ COMMITTED is load-bearing)."""
from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from ledger_pg_support import admin_fetch

from vulnscope.ledger.postgres_backend import PostgresChainBackend
from vulnscope.ledger.verify import verify

pytestmark = pytest.mark.integration
ROUNDS, WRITERS = 20, 16


async def test_new_chain_race(backend: PostgresChainBackend, ledger_db: Any) -> None:
    chains = [f"engagement:{uuid.uuid4()}" for _ in range(ROUNDS)]
    for cid in chains:
        go = asyncio.Event()

        async def writer(i: int, cid: str = cid, go: asyncio.Event = go) -> None:
            await go.wait()
            await backend.append(cid, "policy.decision", "system", {"i": i}, datetime.now(UTC))

        tasks = [asyncio.create_task(writer(i)) for i in range(WRITERS)]
        await asyncio.sleep(0)
        go.set()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        assert [r for r in results if isinstance(r, BaseException)] == []
        assert [e.seq for e in [x async for x in backend.read(cid)]] == list(range(WRITERS))
        assert (await verify(cid, backend)).result == "ok"
    heads = admin_fetch(ledger_db, "SELECT chain_id, seq FROM chain_heads WHERE chain_id = ANY($1::text[])", chains)
    assert sorted(r["chain_id"] for r in heads) == sorted(chains)  # exactly one head row per chain
    assert all(r["seq"] == WRITERS - 1 for r in heads)


async def test_the_read_committed_pin_survives_an_engine_configured_for_repeatable_read(ledger_db: Any) -> None:
    """PB-5: dropping the explicit isolation pin must turn this red. The engine default is
    REPEATABLE READ, under which the first-append race needs the backend's own READ COMMITTED."""
    from ledger_pg_support import app_url, assert_scratch_database
    from sqlalchemy.ext.asyncio import create_async_engine

    engine = create_async_engine(app_url(ledger_db), isolation_level="REPEATABLE READ")
    try:
        await assert_scratch_database(engine)
        rr = PostgresChainBackend(engine)
        for _ in range(5):
            cid = f"engagement:{uuid.uuid4()}"
            go = asyncio.Event()

            async def writer(i: int, cid: str = cid, go: asyncio.Event = go) -> None:
                await go.wait()
                await rr.append(cid, "policy.decision", "system", {"i": i}, datetime.now(UTC))

            tasks = [asyncio.create_task(writer(i)) for i in range(WRITERS)]
            await asyncio.sleep(0)
            go.set()
            results = await asyncio.gather(*tasks, return_exceptions=True)
            assert [r for r in results if isinstance(r, BaseException)] == []
            assert [e.seq for e in [x async for x in rr.read(cid)]] == list(range(WRITERS))
    finally:
        await engine.dispose()
