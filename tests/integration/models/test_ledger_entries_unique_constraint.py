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

import os
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from vulnscope.db.session import get_async_engine

ENV_VAR = "VULNSCOPE_MIGRATION_DATABASE_URL"


@pytest.fixture
def migrator_database_url() -> str:
    url = os.environ.get(ENV_VAR)
    if not url:
        pytest.skip(
            f"{ENV_VAR} not set; this test needs a throwaway, already-migrated "
            "Postgres -- not started this session (see "
            "docs/gates/slice0-plan.md Section 5 Task 0)."
        )
    return url


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
        now = datetime.now(timezone.utc)

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
