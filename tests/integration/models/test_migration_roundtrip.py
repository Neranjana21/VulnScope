"""Alembic migration roundtrip: ``alembic upgrade head`` then ``alembic
downgrade base`` against a throwaway Postgres succeeds cleanly, and
``head`` leaves behind every table ``models/`` defines
(docs/gates/slice0-plan.md Section 3.8, Section 5 Task 0).

The async plumbing in ``alembic/env.py`` is invisible to this test -- it
only shells out to the ``alembic`` CLI as a subprocess (per Section 3.8's
"Tests" description) and inspects the resulting schema afterward; it
never imports ``asyncio``/``AsyncEngine`` itself for the subprocess calls
(only for its own schema-inspection helper).

Skips cleanly (not a failure) when no throwaway migration-role Postgres
is configured -- this slice's implementer was explicitly instructed not
to start any container this session.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
import pytest_asyncio
from sqlalchemy import text

from vulnscope.db.session import get_async_engine

REPO_ROOT = Path(__file__).resolve().parents[3]
ENV_VAR = "VULNSCOPE_MIGRATION_DATABASE_URL"

# tests/integration/_guard.py is a plain helper module, not part of the
# vulnscope package and not reachable via a dotted "tests.integration"
# import (this tree has no __init__.py and this change must not touch
# pyproject.toml's pythonpath) -- so it is loaded by inserting its own
# directory onto sys.path, once, here.
_INTEGRATION_DIR = Path(__file__).resolve().parents[1]
if str(_INTEGRATION_DIR) not in sys.path:
    sys.path.insert(0, str(_INTEGRATION_DIR))

from _guard import require_safe_dev_database_url  # noqa: E402

EXPECTED_TABLES = {
    "orgs",
    "users",
    "api_keys",
    "engagements",
    "scans",
    "findings",
    "evidence",
    "ledger_entries",
    "chain_heads",
    "checkpoints",
    "idempotency_keys",
    "alembic_version",
}


@pytest_asyncio.fixture
async def migration_database_url() -> str:
    return await require_safe_dev_database_url(ENV_VAR)


def _run_alembic(args: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "alembic", *args],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )


async def _table_names(database_url: str) -> set[str]:
    engine = get_async_engine(database_url)
    try:
        async with engine.connect() as conn:
            result = await conn.execute(
                text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
            )
            return {row[0] for row in result}
    finally:
        await engine.dispose()


@pytest.mark.integration
async def test_upgrade_head_then_downgrade_base_roundtrips(migration_database_url: str) -> None:
    env = {
        **os.environ,
        ENV_VAR: migration_database_url,
        "PYTHONPATH": str(REPO_ROOT / "src"),
    }

    try:
        upgrade = _run_alembic(["upgrade", "head"], env)
        assert upgrade.returncode == 0, upgrade.stderr

        tables = await _table_names(migration_database_url)
        missing = EXPECTED_TABLES - tables
        assert not missing, f"missing tables after upgrade head: {missing}"

        downgrade = _run_alembic(["downgrade", "base"], env)
        assert downgrade.returncode == 0, downgrade.stderr

        tables_after_downgrade = await _table_names(migration_database_url)
        assert "ledger_entries" not in tables_after_downgrade
        assert "orgs" not in tables_after_downgrade
    finally:
        # Leave the throwaway database migrated to head regardless of
        # assertion outcome, so other integration tests sharing this
        # database (role-restriction, mutation-trigger, unique-constraint)
        # are never left looking at a half-torn-down schema.
        _run_alembic(["upgrade", "head"], env)
