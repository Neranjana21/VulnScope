"""``ledger_entries`` carries ``UNIQUE(chain_id, seq)`` (fixes pre-gate
finding SEC-5): a raw duplicate-``(chain_id, seq)`` SQL ``INSERT``
(bypassing any application-level ``chain_heads`` lock, to simulate a lock
bug) raises ``IntegrityError`` on the second insert, not a silent
double-write/fork.

Runs as ``vulnscope_migrator`` (needs no restricted-role concerns of its
own -- that is ``test_ledger_role_restricted.py``'s job; this test is
only about the constraint itself). Task B's
``test_postgres_concurrency.py`` separately exercises this constraint
under real concurrent load via the backend's ``append()``.

Skips cleanly (not a failure) when no throwaway Postgres is configured.
"""
from __future__ import annotations

import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from vulnscope.db.session import get_async_engine

ENV_VAR = "VULNSCOPE_MIGRATION_DATABASE_URL"

# See tests/integration/models/test_migration_roundtrip.py's identical
# comment: tests/integration/_guard.py is loaded via a sys.path insertion,
# not a dotted package import, since this tree has no __init__.py and
# this change must not touch pyproject.toml's pythonpath.
_INTEGRATION_DIR = Path(__file__).resolve().parents[1]
if str(_INTEGRATION_DIR) not in sys.path:
    sys.path.insert(0, str(_INTEGRATION_DIR))

from _guard import require_safe_dev_database_url  # noqa: E402


@pytest_asyncio.fixture
async def migrator_database_url() -> str:
    return await require_safe_dev_database_url(ENV_VAR)


@pytest.mark.integration
async def test_duplicate_chain_id_seq_raises_integrity_error(migrator_database_url: str) -> None:
    engine = get_async_engine(migrator_database_url)
    try:
        chain_id = f"engagement:{uuid.uuid4()}"
        insert_sql = text(
            "INSERT INTO ledger_entries "
            "(id, schema_version, chain_id, seq, kind, actor, payload, ts, "
            "prev_hash, record_hash) "
            "VALUES (:id, 1, :chain_id, 0, 'policy.decision', 'system', '{}'::jsonb, "
            ":ts, :prev_hash, :record_hash)"
        )
        now = datetime.now(UTC)

        async with engine.begin() as conn:
            await conn.execute(
                insert_sql,
                {
                    "id": str(uuid.uuid4()),
                    "chain_id": chain_id,
                    "ts": now,
                    "prev_hash": "a" * 64,
                    "record_hash": "b" * 64,
                },
            )

        with pytest.raises(IntegrityError):
            async with engine.begin() as conn:
                # Same (chain_id, seq) pair as above, deliberately -- this
                # is exactly what a buggy/bypassed chain_heads lock would
                # produce: two writers computing the same "next seq".
                await conn.execute(
                    insert_sql,
                    {
                        "id": str(uuid.uuid4()),
                        "chain_id": chain_id,
                        "ts": now,
                        "prev_hash": "c" * 64,
                        "record_hash": "d" * 64,
                    },
                )
    finally:
        await engine.dispose()
