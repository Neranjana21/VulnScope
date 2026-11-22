# ruff: noqa: E501
"""SEC-5 backstop with the real backend: the UNIQUE constraint and the head cross-check (F7) fail
LOUD when ``chain_heads`` is rewound or advanced by a compromised app role; nothing partial."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from ledger_pg_support import app_url
from sqlalchemy import exc as sa_exc
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from vulnscope.ledger.errors import LedgerStorageError
from vulnscope.ledger.postgres_backend import PostgresChainBackend
from vulnscope.ledger.verify import verify

pytestmark = pytest.mark.integration


async def _seed(backend: PostgresChainBackend, n: int = 4) -> str:
    cid = f"engagement:{uuid.uuid4()}"
    for i in range(n):
        await backend.append(cid, "policy.decision", "system", {"i": i}, datetime.now(UTC))
    return cid


async def test_raw_duplicate_seq_insert_as_the_app_role_is_a_unique_violation(
    backend: PostgresChainBackend, ledger_db: Any
) -> None:
    cid = await _seed(backend)
    engine = create_async_engine(app_url(ledger_db))
    try:
        with pytest.raises(sa_exc.IntegrityError):
            async with engine.begin() as conn:
                await conn.execute(
                    text(
                        "INSERT INTO ledger_entries (id, schema_version, chain_id, seq, kind, actor, "
                        "payload, ts, prev_hash, record_hash) VALUES (:id, 1, :c, 0, 'evidence', 'system', "
                        "'{}'::json, now(), :h, :h)"
                    ),
                    {"id": str(uuid.uuid4()), "c": cid, "h": "ab" * 32},
                )
    finally:
        await engine.dispose()
    assert (await verify(cid, backend)).result == "ok"


@pytest.mark.parametrize("delta", [-1, 5])
async def test_a_rewound_or_advanced_head_row_fails_loud_and_writes_nothing(
    backend: PostgresChainBackend, ledger_db: Any, delta: int
) -> None:
    cid = await _seed(backend)
    before = [e async for e in backend.read(cid)]
    engine = create_async_engine(app_url(ledger_db))
    try:
        async with engine.begin() as conn:  # the app role CAN update chain_heads (D1 design)
            await conn.execute(
                text("UPDATE chain_heads SET seq = seq + :d, head_hash = :h WHERE chain_id = :c"),
                {"d": delta, "h": "cd" * 32 if delta > 0 else before[-2].record_hash, "c": cid},
            )
    finally:
        await engine.dispose()
    with pytest.raises(LedgerStorageError) as info:
        await backend.append(cid, "policy.decision", "system", {"x": 1}, datetime.now(UTC))
    assert info.value.code in ("head_diverged", "unique_violation")
    after = [e async for e in backend.read(cid)]
    assert after == before  # nothing partial, nothing written
    assert (await verify(cid, backend)).result == "ok"  # the old chain is still intact
