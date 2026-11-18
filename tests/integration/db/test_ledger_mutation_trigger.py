"""Defense-in-depth mutation-rejection trigger (design C,
docs/gates/slice0-plan.md Section 3.10): ``UPDATE``/``DELETE``/``TRUNCATE``
against ``ledger_entries``/``checkpoints`` raise the trigger's own
exception even for ``vulnscope_migrator`` (the table owner, who has no
``GRANT``-level restriction standing in the way) -- proving the guard is
structural, not merely a privilege gap. ``vulnscope_app``'s complementary
case (blocked earlier, by missing privilege, before the trigger is ever
reached) is already covered by
``tests/integration/db/test_ledger_role_restricted.py``; together the two
files prove the guard holds for both roles, by two different, independent
mechanisms.

Also proves (owner's explicit requirement, beyond the plan's own test
list): the trigger still fires when ``session_replication_role =
replica`` is set for the session/transaction -- exactly what
``ENABLE ALWAYS TRIGGER`` (INFRA-5's fix) is supposed to guarantee.

A separate case documents the known, acceptable break-glass path
(``ALTER TABLE ... DISABLE TRIGGER`` as the owner role) as a documented
limitation, not a failure -- and re-enables the trigger afterward so it
does not leak a disabled-trigger state into any other test sharing this
throwaway database.

Skips cleanly (not a failure) when no throwaway, already-migrated
Postgres reachable as ``vulnscope_migrator`` is configured -- not started
this session.
"""
from __future__ import annotations

import sys
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from vulnscope.db.session import get_async_engine

MIGRATOR_ENV_VAR = "VULNSCOPE_MIGRATION_DATABASE_URL"

# See tests/integration/models/test_migration_roundtrip.py's identical
# comment: tests/integration/_guard.py is loaded via a sys.path insertion,
# not a dotted package import, since this tree has no __init__.py and
# this change must not touch pyproject.toml's pythonpath.
_INTEGRATION_DIR = Path(__file__).resolve().parents[1]
if str(_INTEGRATION_DIR) not in sys.path:
    sys.path.insert(0, str(_INTEGRATION_DIR))

from _dbkit import assert_pg_error  # noqa: E402
from _guard import require_safe_dev_database_url  # noqa: E402


@pytest_asyncio.fixture
async def migrator_database_url() -> str:
    return await require_safe_dev_database_url(MIGRATOR_ENV_VAR)


def _assert_append_only_violation(exc: BaseException) -> None:
    assert_pg_error(exc, sqlstate="P0001", exc_name="RaiseError", message="append-only")


async def _insert_one_row(conn: AsyncConnection, chain_id: str) -> None:
    await conn.execute(
        text(
            "INSERT INTO ledger_entries "
            "(id, schema_version, chain_id, seq, kind, actor, payload, ts, "
            "prev_hash, record_hash) "
            "VALUES (:id, 1, :chain_id, 0, 'policy.decision', 'system', '{}'::jsonb, "
            ":ts, :prev_hash, :record_hash)"
        ),
        {
            "id": str(uuid.uuid4()),
            "chain_id": chain_id,
            "ts": datetime.now(UTC),
            "prev_hash": "a" * 64,
            "record_hash": "b" * 64,
        },
    )


@pytest_asyncio.fixture
async def migrator_engine(migrator_database_url: str) -> AsyncIterator[object]:
    engine = get_async_engine(migrator_database_url)
    try:
        yield engine
    finally:
        await engine.dispose()


@pytest.mark.integration
@pytest.mark.parametrize(
    "statement_template",
    [
        "UPDATE ledger_entries SET kind = 'x' WHERE chain_id = :chain_id",
        "DELETE FROM ledger_entries WHERE chain_id = :chain_id",
    ],
)
async def test_trigger_blocks_mutation_for_owner_role(
    migrator_engine: AsyncEngine, statement_template: str
) -> None:
    chain_id = f"engagement:{uuid.uuid4()}"
    async with migrator_engine.begin() as conn:
        await _insert_one_row(conn, chain_id)

    with pytest.raises(DBAPIError) as exc_info:
        async with migrator_engine.begin() as conn:
            await conn.execute(text(statement_template), {"chain_id": chain_id})
    _assert_append_only_violation(exc_info.value)


@pytest.mark.integration
async def test_trigger_blocks_truncate_for_owner_role(migrator_engine: AsyncEngine) -> None:
    chain_id = f"engagement:{uuid.uuid4()}"
    async with migrator_engine.begin() as conn:
        await _insert_one_row(conn, chain_id)

    with pytest.raises(DBAPIError) as exc_info:
        async with migrator_engine.begin() as conn:
            await conn.execute(text("TRUNCATE ledger_entries"))
    _assert_append_only_violation(exc_info.value)


@pytest.mark.integration
async def test_trigger_still_fires_under_replica_session_replication_role(
    migrator_engine: AsyncEngine,
) -> None:
    """ENABLE ALWAYS TRIGGER (INFRA-5's fix): the guard must hold even for
    rows applied under session_replication_role = replica (the role a
    logical-replication apply process runs under)."""
    chain_id = f"engagement:{uuid.uuid4()}"
    async with migrator_engine.begin() as conn:
        await _insert_one_row(conn, chain_id)

    with pytest.raises(DBAPIError) as exc_info:
        async with migrator_engine.begin() as conn:
            await conn.execute(text("SET session_replication_role = replica"))
            await conn.execute(
                text("UPDATE ledger_entries SET kind = 'x' WHERE chain_id = :chain_id"),
                {"chain_id": chain_id},
            )
    _assert_append_only_violation(exc_info.value)


@pytest.mark.integration
async def test_disable_trigger_break_glass_path_is_documented_limitation(
    migrator_engine: AsyncEngine,
) -> None:
    """ALTER TABLE ... DISABLE TRIGGER is the one acknowledged bypass
    (table-owner/superuser DDL rights can always remove the guard before
    mutating) -- this test documents that it is a real, working bypass,
    not a failure of the guard, and restores the trigger afterward."""
    chain_id = f"engagement:{uuid.uuid4()}"
    async with migrator_engine.begin() as conn:
        await _insert_one_row(conn, chain_id)

    try:
        async with migrator_engine.begin() as conn:
            await conn.execute(text("ALTER TABLE ledger_entries DISABLE TRIGGER ALL"))
            await conn.execute(
                text("UPDATE ledger_entries SET kind = 'x' WHERE chain_id = :chain_id"),
                {"chain_id": chain_id},
            )
        async with migrator_engine.connect() as conn:
            result = await conn.execute(
                text("SELECT kind FROM ledger_entries WHERE chain_id = :chain_id"),
                {"chain_id": chain_id},
            )
            assert result.scalar_one() == "x"
    finally:
        async with migrator_engine.begin() as conn:
            await conn.execute(text("ALTER TABLE ledger_entries ENABLE TRIGGER ALL"))
