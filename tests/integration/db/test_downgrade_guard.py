# ruff: noqa: E501
"""L8 (docs/gates/slice0-plan.md 3.10.1, GR-SEC-8 / GR-STR-27): ``alembic downgrade base`` drops
``ledger_entries`` and ``checkpoints`` without firing the mutation triggers, so it must refuse on
any database that is not marked ``dev-disposable`` while the ledger is non-empty, and must work
on a marked one. Scratch databases only; nothing here touches the shared database.

No assertion below is written over a DSN, URL, password or fixture object (pytest prints the
operands of a failed assertion); only plain values computed beforehand.
"""
from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

_INTEGRATION_DIR = Path(__file__).resolve().parents[1]
if str(_INTEGRATION_DIR) not in sys.path:
    sys.path.insert(0, str(_INTEGRATION_DIR))

from _dbkit import insert_ledger_row, kit  # noqa: E402

EXPECTED_TABLES = {
    "orgs", "users", "api_keys", "engagements", "scans", "findings", "evidence",
    "ledger_entries", "chain_heads", "checkpoints", "idempotency_keys", "alembic_version",
}


def _public_tables(db: Any) -> set[str]:
    return {t.removeprefix("public.") for t in kit().user_tables(db)}


@pytest.mark.integration
def test_downgrade_refused_when_unmarked_and_ledger_nonempty(
    scratch_db_factory: Callable[..., Any], stress_env: Any
) -> None:
    k = kit()
    db = scratch_db_factory()
    insert_ledger_row(db)
    k.execute(k.to_dsn(stress_env.admin_url), f'ALTER DATABASE "{db.name}" RESET vulnscope.env')
    marker = k.fetchval(db.admin_dsn, "SELECT current_setting('vulnscope.env', true)")
    assert marker in (None, ""), "the dev-disposable marker is still set; the test setup is wrong"

    proc = k.alembic(stress_env, db, "downgrade", "base")
    returncode, stderr = proc.returncode, proc.stderr

    assert returncode != 0, "downgrade base succeeded on an unmarked database with a non-empty ledger"
    assert "refusing to downgrade" in stderr, "downgrade failed, but not through the L8 guard"
    remaining = _public_tables(db)
    assert EXPECTED_TABLES <= remaining, f"tables were dropped: {sorted(EXPECTED_TABLES - remaining)}"


@pytest.mark.integration
def test_downgrade_allowed_when_marked(
    scratch_db_factory: Callable[..., Any], stress_env: Any
) -> None:
    k = kit()
    db = scratch_db_factory()
    insert_ledger_row(db)
    marker = k.fetchval(db.admin_dsn, "SELECT current_setting('vulnscope.env', true)")
    assert marker == "dev-disposable", "the scratch database is not marked dev-disposable"

    proc = k.alembic(stress_env, db, "downgrade", "base")
    returncode, stderr = proc.returncode, proc.stderr

    assert returncode == 0, f"downgrade base failed on a marked database: {stderr[-800:]}"
    remaining = _public_tables(db)
    assert remaining == {"alembic_version"}, f"unexpected tables after downgrade: {sorted(remaining)}"
