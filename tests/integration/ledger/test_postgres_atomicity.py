# ruff: noqa: E501
"""Single-transaction atomicity: a failure at the LAST statement leaves no entry and no head move;
a cancelled append that is waiting on the head lock leaves no gap."""
from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from ledger_pg_support import admin_dsn, admin_fetch, open_backend
from sqlalchemy import event

from vulnscope.ledger.errors import LedgerStorageError
from vulnscope.ledger.postgres_backend import PostgresChainBackend
from vulnscope.ledger.verify import verify

pytestmark = pytest.mark.integration


async def test_failure_at_the_head_update_rolls_the_entry_back(ledger_db: Any) -> None:
    cid = f"engagement:{uuid.uuid4()}"
    engine, backend = await open_backend(ledger_db)
    try:
        await backend.append(cid, "policy.decision", "system", {"i": 0}, datetime.now(UTC))
        armed = {"on": True}

        @event.listens_for(engine.sync_engine, "before_cursor_execute")
        def boom(conn: Any, cursor: Any, statement: str, *a: Any) -> None:
            if armed["on"] and statement.lstrip().upper().startswith("UPDATE CHAIN_HEADS"):
                raise RuntimeError("injected failure at the last statement")

        with pytest.raises(LedgerStorageError):
            await backend.append(cid, "policy.decision", "system", {"i": 1}, datetime.now(UTC))
        armed["on"] = False
        rows = admin_fetch(ledger_db, "SELECT seq FROM ledger_entries WHERE chain_id = $1 ORDER BY seq", cid)
        assert [r["seq"] for r in rows] == [0]  # the entry insert was rolled back
        head = admin_fetch(ledger_db, "SELECT seq FROM chain_heads WHERE chain_id = $1", cid)
        assert [r["seq"] for r in head] == [0]
        nxt = await backend.append(cid, "policy.decision", "system", {"i": 1}, datetime.now(UTC))
        assert nxt.seq == 1  # the same seq is reused: no gap
        assert (await verify(cid, backend)).result == "ok"
    finally:
        await engine.dispose()


async def test_cancelling_an_append_blocked_on_the_head_lock_leaves_no_gap(
    backend: PostgresChainBackend, ledger_db: Any
) -> None:
    import asyncpg

    cid = f"engagement:{uuid.uuid4()}"
    await backend.append(cid, "policy.decision", "system", {"i": 0}, datetime.now(UTC))
    holder = await asyncpg.connect(admin_dsn(ledger_db))
    try:
        tx = holder.transaction()
        await tx.start()
        await holder.fetch("SELECT seq FROM chain_heads WHERE chain_id = $1 FOR UPDATE", cid)
        blocked = asyncio.create_task(
            backend.append(cid, "policy.decision", "system", {"i": "blocked"}, datetime.now(UTC))
        )
        await asyncio.sleep(0.4)
        assert not blocked.done()
        blocked.cancel()
        with pytest.raises(asyncio.CancelledError):
            await blocked
        await tx.commit()
    finally:
        await holder.close()
    nxt = await backend.append(cid, "policy.decision", "system", {"i": 1}, datetime.now(UTC))
    assert nxt.seq == 1
    assert (await verify(cid, backend)).result == "ok"
    assert backend._gates == {}  # the gate entry was released on cancellation
