# ruff: noqa: E501
"""What the backend actually sends: no UPDATE/DELETE/TRUNCATE on ledger_entries or checkpoints,
UPDATE only on chain_heads, and every append runs inside a READ COMMITTED transaction."""
from __future__ import annotations

import asyncio
import re
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from ledger_pg_support import open_backend
from sqlalchemy import event

from vulnscope.ledger.checkpoint import InMemoryCheckpointStore, maybe_checkpoint
from vulnscope.ledger.postgres_backend import PostgresCheckpointStore
from vulnscope.ledger.verify import verify

pytestmark = pytest.mark.integration


class _NullSigner:
    public_key_hex = "00" * 32

    def sign(self, payload: bytes) -> bytes:
        return b"\x00" * 64

    def verify(self, payload: bytes, signature: bytes) -> bool:
        return True


async def test_recorded_sql_over_a_mixed_workload(ledger_db: Any) -> None:
    engine, backend = await open_backend(ledger_db)
    seen: list[str] = []
    isolation: list[str] = []
    busy = {"in_hook": False}

    @event.listens_for(engine.sync_engine, "before_cursor_execute")
    def record(conn: Any, cursor: Any, statement: str, *a: Any) -> None:
        if busy["in_hook"]:
            return
        seen.append(statement)
        if statement.lstrip().upper().startswith("INSERT INTO LEDGER_ENTRIES"):
            busy["in_hook"] = True
            try:  # same connection, same transaction as the append
                isolation.append(conn.exec_driver_sql("SHOW transaction_isolation").scalar_one())
            finally:
                busy["in_hook"] = False

    try:
        cid = f"engagement:{uuid.uuid4()}"
        await asyncio.gather(
            *(backend.append(cid, "policy.decision", "system", {"i": i}, datetime.now(UTC)) for i in range(20))
        )
        [e async for e in backend.read(cid)]
        await backend.head(cid)
        await backend.record_count(cid)
        await verify(cid, backend)
        store = PostgresCheckpointStore(engine)
        await maybe_checkpoint(cid, backend, _NullSigner(), store=store, ts=datetime.now(UTC), force=True)
        await maybe_checkpoint(cid, backend, _NullSigner(), store=InMemoryCheckpointStore(), ts=datetime.now(UTC), force=True)
    finally:
        await engine.dispose()

    dml = [s for s in seen if re.match(r"\s*(UPDATE|DELETE|TRUNCATE)\b", s, re.I)]
    assert dml and all(re.match(r"\s*UPDATE\s+chain_heads\b", s, re.I) for s in dml)
    assert not any(re.search(r"\b(DELETE\s+FROM|TRUNCATE)\b", s, re.I) for s in seen)
    assert not any(re.match(r"\s*UPDATE\s+(ledger_entries|checkpoints)\b", s, re.I) for s in seen)
    assert isolation and set(isolation) == {"read committed"}
