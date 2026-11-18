# ruff: noqa: E501
"""Alembic migration roundtrip on a per-test scratch database (docs/gates/slice0-plan.md 3.8,
3.10.1 L5): ``alembic upgrade head`` then ``alembic downgrade base`` succeeds cleanly, ``head``
leaves every table ``models/`` defines, ``base`` leaves only ``alembic_version`` (the app role
still exists), and a following ``upgrade head`` passes ``verify_effective_privileges``.

Runs on a scratch database from the R1 plugin's ``scratch_db_factory``, never the shared
``vulnscope`` database, so an aborted run cannot leave the shared database empty. Subprocess
calls only for alembic itself. Assertions are over plain values (no DSN, URL or fixture object).
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

from _dbkit import kit, table_grants  # noqa: E402

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


def _public_tables(db: Any) -> set[str]:
    return {t.removeprefix("public.") for t in kit().user_tables(db)}


@pytest.mark.integration
def test_upgrade_head_then_downgrade_base_roundtrips(
    scratch_db_factory: Callable[..., Any], stress_env: Any
) -> None:
    k = kit()
    db = scratch_db_factory(migrate=False)

    upgrade = k.alembic(stress_env, db, "upgrade", "head")
    upgrade_rc, upgrade_err = upgrade.returncode, upgrade.stderr
    assert upgrade_rc == 0, upgrade_err[-800:]
    after_upgrade = _public_tables(db)
    missing = EXPECTED_TABLES - after_upgrade
    assert not missing, f"missing tables after upgrade head: {sorted(missing)}"

    downgrade = k.alembic(stress_env, db, "downgrade", "base")
    downgrade_rc, downgrade_err = downgrade.returncode, downgrade.stderr
    assert downgrade_rc == 0, downgrade_err[-800:]
    after_downgrade = _public_tables(db)
    assert after_downgrade == {"alembic_version"}, f"left after downgrade: {sorted(after_downgrade)}"
    role_count = k.fetchval(db.admin_dsn, "SELECT count(*) FROM pg_roles WHERE rolname = 'vulnscope_app'")
    assert role_count == 1, "downgrade must never drop the app role"


@pytest.mark.integration
def test_upgrade_after_downgrade_passes_verify(
    scratch_db_factory: Callable[..., Any], stress_env: Any
) -> None:
    k = kit()
    mg = k.lazy("vulnscope.db.migration_grants")
    db = scratch_db_factory()

    downgrade = k.alembic(stress_env, db, "downgrade", "base")
    downgrade_rc, downgrade_err = downgrade.returncode, downgrade.stderr
    assert downgrade_rc == 0, downgrade_err[-800:]
    upgrade = k.alembic(stress_env, db, "upgrade", "head")
    upgrade_rc, upgrade_err = upgrade.returncode, upgrade.stderr
    assert upgrade_rc == 0, upgrade_err[-800:]

    grants = table_grants()
    k.run_sync_helper(db.admin_url, lambda c: mg.verify_effective_privileges(c, mg.APP_ROLE, grants))
