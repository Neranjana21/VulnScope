# ruff: noqa: E501
"""Real SQLSTATE mapping and secret safety against the real driver: a SELECT-only role, a held
lock, a wrong parameter type; the canary payload never reaches an error, a traceback or __cause__."""
from __future__ import annotations

import asyncio
import traceback
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from ledger_pg_support import admin_dsn, admin_exec, app_url, open_backend
from sqlalchemy.ext.asyncio import create_async_engine

from vulnscope.ledger.errors import LedgerStorageError
from vulnscope.ledger.postgres_backend import PostgresChainBackend

pytestmark = pytest.mark.integration
CANARY = "CANARY-ERR-" + uuid.uuid4().hex


def _clean(err: BaseException) -> None:
    assert err.__cause__ is None and err.__context__ is None
    text = "".join(traceback.format_exception(err, chain=True)) + repr(err) + str(err)
    assert CANARY not in text


async def test_select_only_role_maps_to_insufficient_privilege(
    request: pytest.FixtureRequest, ledger_db: Any
) -> None:
    from vulnscope_db_plugin import with_user

    mgr = request.getfixturevalue("scratch_manager")
    name, pw = mgr.new_role(ledger_db)
    admin_exec(
        ledger_db,
        f'GRANT CONNECT ON DATABASE "{ledger_db.name}" TO "{name}"',
        f'GRANT SELECT ON ALL TABLES IN SCHEMA public TO "{name}"',
    )
    from stress_db_secrets import reveal

    engine = create_async_engine(reveal(with_user(app_url(ledger_db), name, pw)))
    try:
        backend = PostgresChainBackend(engine)
        with pytest.raises(LedgerStorageError) as info:
            await backend.append(
                f"engagement:{uuid.uuid4()}", "policy.decision", "system", {"t": CANARY}, datetime.now(UTC)
            )
        assert (info.value.code, info.value.sqlstate) == ("insufficient_privilege", "42501")
        _clean(info.value)
    finally:
        await engine.dispose()
        mgr.drop_role(ledger_db, name)


async def test_a_held_head_lock_maps_to_lock_timeout(ledger_db: Any) -> None:
    import asyncpg

    cid = f"engagement:{uuid.uuid4()}"
    engine, backend = await open_backend(ledger_db, lock_timeout_ms=300)
    try:
        await backend.append(cid, "policy.decision", "system", {"i": 0}, datetime.now(UTC))
        holder = await asyncpg.connect(admin_dsn(ledger_db))
        try:
            tx = holder.transaction()
            await tx.start()
            await holder.fetch("SELECT seq FROM chain_heads WHERE chain_id = $1 FOR UPDATE", cid)
            with pytest.raises(LedgerStorageError) as info:
                await backend.append(cid, "policy.decision", "system", {"t": CANARY}, datetime.now(UTC))
            assert (info.value.code, info.value.sqlstate) == ("lock_timeout", "55P03")
            _clean(info.value)
            await tx.rollback()
        finally:
            await holder.close()
    finally:
        await engine.dispose()


async def test_an_exhausted_pool_maps_to_pool_timeout_without_the_payload(ledger_db: Any) -> None:
    pooled = create_async_engine(app_url(ledger_db), pool_size=1, max_overflow=0, pool_timeout=0.3)
    try:
        backend = PostgresChainBackend(pooled)
        async with pooled.connect():  # hold the only connection
            with pytest.raises(LedgerStorageError) as info:
                await asyncio.wait_for(
                    backend.append(
                        f"engagement:{uuid.uuid4()}", "policy.decision", "system", {"t": CANARY}, datetime.now(UTC)
                    ),
                    timeout=5,
                )
        assert info.value.code == "pool_timeout"
        _clean(info.value)
    finally:
        await pooled.dispose()
