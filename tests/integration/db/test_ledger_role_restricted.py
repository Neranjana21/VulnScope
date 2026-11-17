"""As ``vulnscope_app`` (infra/postgres/init-roles.sql, design C,
docs/gates/slice0-plan.md Section 3.10):

- **positive**: ``INSERT``/``SELECT`` on ``ledger_entries``/``checkpoints``
  succeed; ``SELECT ... FOR UPDATE`` and ``UPDATE`` on ``chain_heads``
  succeed (the lock-target design that resolves the ``SELECT ... FOR
  UPDATE``-requires-``UPDATE`` privilege contradiction without granting
  ``UPDATE`` on ``ledger_entries`` itself).
- **negative**: ``UPDATE``, ``DELETE``, ``TRUNCATE``, and ``SELECT ... FOR
  UPDATE`` against ``ledger_entries``/``checkpoints`` all raise a
  permissions error; ``DELETE``/``TRUNCATE`` against ``chain_heads`` also
  raise (rows are only ever updated there, never removed).

Skips cleanly (not a failure) when no throwaway, already-migrated
Postgres reachable as the restricted ``vulnscope_app`` role is configured
-- not started this session.
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone

import pytest
from asyncpg.exceptions import InsufficientPrivilegeError
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from vulnscope.db.session import get_async_engine

APP_ENV_VAR = "VULNSCOPE_TEST_APP_DATABASE_URL"

LEDGER_ENTRIES_NEGATIVE_STATEMENTS = [
    "UPDATE ledger_entries SET kind = 'x' WHERE seq = -999",
    "DELETE FROM ledger_entries WHERE seq = -999",
    "TRUNCATE ledger_entries",
    "SELECT * FROM ledger_entries WHERE seq = -999 FOR UPDATE",
]

CHECKPOINTS_NEGATIVE_STATEMENTS = [
    "UPDATE checkpoints SET signature = 'x' WHERE seq = -999",
    "DELETE FROM checkpoints WHERE seq = -999",
    "TRUNCATE checkpoints",
    "SELECT * FROM checkpoints WHERE seq = -999 FOR UPDATE",
]

CHAIN_HEADS_NEGATIVE_STATEMENTS = [
    "DELETE FROM chain_heads WHERE chain_id = 'does-not-exist'",
    "TRUNCATE chain_heads",
]


@pytest.fixture
def app_database_url() -> str:
    url = os.environ.get(APP_ENV_VAR)
    if not url:
        pytest.skip(
            f"{APP_ENV_VAR} not set; this test needs a throwaway, migrated "
            "Postgres reachable as the restricted vulnscope_app role -- not "
            "started this session (see docs/gates/slice0-plan.md Section 3.10)."
        )
    return url


def _assert_insufficient_privilege(exc: BaseException) -> None:
    assert isinstance(exc, DBAPIError), f"expected DBAPIError, got {type(exc)}: {exc}"
    assert isinstance(exc.orig, InsufficientPrivilegeError), (
        f"expected InsufficientPrivilegeError, got {type(exc.orig)}: {exc.orig}"
    )


@pytest.mark.integration
async def test_app_role_can_insert_and_select_ledger_entries(app_database_url: str) -> None:
    engine = get_async_engine(app_database_url)
    try:
        chain_id = f"engagement:{uuid.uuid4()}"
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO ledger_entries "
                    "(id, schema_version, chain_id, seq, kind, actor, payload, ts, "
                    "prev_hash, record_hash) "
                    "VALUES (:id, 1, :chain_id, 0, 'policy.decision', 'system', "
                    "'{}'::jsonb, :ts, :prev_hash, :record_hash)"
                ),
                {
                    "id": str(uuid.uuid4()),
                    "chain_id": chain_id,
                    "ts": datetime.now(timezone.utc),
                    "prev_hash": "a" * 64,
                    "record_hash": "b" * 64,
                },
            )
        async with engine.connect() as conn:
            result = await conn.execute(
                text("SELECT count(*) FROM ledger_entries WHERE chain_id = :chain_id"),
                {"chain_id": chain_id},
            )
            assert result.scalar_one() == 1
    finally:
        await engine.dispose()


@pytest.mark.integration
async def test_app_role_can_insert_and_select_checkpoints(app_database_url: str) -> None:
    engine = get_async_engine(app_database_url)
    try:
        chain_id = f"engagement:{uuid.uuid4()}"
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO checkpoints (id, chain_id, seq, head_hash, ts, signature) "
                    "VALUES (:id, :chain_id, 0, :head_hash, :ts, :signature)"
                ),
                {
                    "id": str(uuid.uuid4()),
                    "chain_id": chain_id,
                    "head_hash": "c" * 64,
                    "ts": datetime.now(timezone.utc),
                    "signature": "d" * 128,
                },
            )
        async with engine.connect() as conn:
            result = await conn.execute(
                text("SELECT count(*) FROM checkpoints WHERE chain_id = :chain_id"),
                {"chain_id": chain_id},
            )
            assert result.scalar_one() == 1
    finally:
        await engine.dispose()


@pytest.mark.integration
async def test_app_role_can_lock_and_update_chain_heads(app_database_url: str) -> None:
    engine = get_async_engine(app_database_url)
    try:
        chain_id = f"engagement:{uuid.uuid4()}"
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO chain_heads (chain_id, seq, head_hash) "
                    "VALUES (:chain_id, -1, :head_hash)"
                ),
                {"chain_id": chain_id, "head_hash": "0" * 64},
            )
        async with engine.begin() as conn:
            locked = await conn.execute(
                text("SELECT seq, head_hash FROM chain_heads WHERE chain_id = :chain_id FOR UPDATE"),
                {"chain_id": chain_id},
            )
            row = locked.one()
            assert row.seq == -1
            await conn.execute(
                text("UPDATE chain_heads SET seq = 0, head_hash = :head_hash WHERE chain_id = :chain_id"),
                {"chain_id": chain_id, "head_hash": "1" * 64},
            )
        async with engine.connect() as conn:
            verify = await conn.execute(
                text("SELECT seq FROM chain_heads WHERE chain_id = :chain_id"),
                {"chain_id": chain_id},
            )
            assert verify.scalar_one() == 0
    finally:
        await engine.dispose()


@pytest.mark.integration
@pytest.mark.parametrize("statement", LEDGER_ENTRIES_NEGATIVE_STATEMENTS)
async def test_app_role_cannot_mutate_or_lock_ledger_entries(
    app_database_url: str, statement: str
) -> None:
    engine = get_async_engine(app_database_url)
    try:
        with pytest.raises(DBAPIError) as exc_info:
            async with engine.begin() as conn:
                await conn.execute(text(statement))
        _assert_insufficient_privilege(exc_info.value)
    finally:
        await engine.dispose()


@pytest.mark.integration
@pytest.mark.parametrize("statement", CHECKPOINTS_NEGATIVE_STATEMENTS)
async def test_app_role_cannot_mutate_or_lock_checkpoints(
    app_database_url: str, statement: str
) -> None:
    engine = get_async_engine(app_database_url)
    try:
        with pytest.raises(DBAPIError) as exc_info:
            async with engine.begin() as conn:
                await conn.execute(text(statement))
        _assert_insufficient_privilege(exc_info.value)
    finally:
        await engine.dispose()


@pytest.mark.integration
@pytest.mark.parametrize("statement", CHAIN_HEADS_NEGATIVE_STATEMENTS)
async def test_app_role_cannot_delete_or_truncate_chain_heads(
    app_database_url: str, statement: str
) -> None:
    engine = get_async_engine(app_database_url)
    try:
        with pytest.raises(DBAPIError) as exc_info:
            async with engine.begin() as conn:
                await conn.execute(text(statement))
        _assert_insufficient_privilege(exc_info.value)
    finally:
        await engine.dispose()
