# ruff: noqa: E501
"""L3 and L4 (docs/gates/slice0-plan.md 3.10.1): the grant block is idempotent, drift made by the
table owner is healed by a re-run, and drift the helper cannot heal (a privilege granted by a
third role) is detected, not silently kept. Scratch databases only.

``vulnscope.db.migration_grants`` is imported lazily inside each test body (GR-STR-20). No
assertion is written over a DSN, URL, password or fixture object.
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

from _dbkit import kit, snapshot, table_grants  # noqa: E402

MG = "vulnscope.db.migration_grants"

# Owner-made drift; each must be erased by re-applying the grant statements (L4).
OWNER_DRIFT = {
    "ledger_update_delete_truncate": 'GRANT UPDATE, DELETE, TRUNCATE ON ledger_entries TO "vulnscope_app"',
    "public_all_chain_heads": "GRANT ALL ON chain_heads TO PUBLIC",
    "column_grant_ledger": 'GRANT UPDATE (kind) ON ledger_entries TO "vulnscope_app"',
    "public_all_alembic_version": "GRANT ALL ON alembic_version TO PUBLIC",
    "grant_option": 'GRANT SELECT ON orgs TO "vulnscope_app" WITH GRANT OPTION',
}


def _apply(db: Any, mg: Any, grants: dict[str, tuple[str, ...]]) -> None:
    statements = mg.grant_statements(mg.APP_ROLE, grants)
    kit().run_sync_helper(db.admin_url, lambda c: mg.apply_statements(c, statements))


def _verify(db: Any, mg: Any, grants: dict[str, tuple[str, ...]]) -> None:
    kit().run_sync_helper(db.admin_url, lambda c: mg.verify_effective_privileges(c, mg.APP_ROLE, grants))


def _app_role_has_grants(snap: list[tuple[str, ...]]) -> bool:
    """True if the snapshot shows the app role holding a privilege on ``orgs`` (not vacuous)."""
    return any(row[1] == "orgs" and "vulnscope_app" in row[5] for row in snap)


@pytest.mark.integration
def test_apply_statements_twice_is_idempotent(scratch_db_factory: Callable[..., Any]) -> None:
    mg = kit().lazy(MG)
    db = scratch_db_factory()
    grants = table_grants()
    before = snapshot(db)
    assert _app_role_has_grants(before), "the migration granted the app role nothing"

    _apply(db, mg, grants)
    once = snapshot(db)
    _apply(db, mg, grants)
    twice = snapshot(db)

    assert once == before
    assert twice == before


@pytest.mark.integration
def test_alembic_upgrade_head_rerun_is_noop(
    scratch_db_factory: Callable[..., Any], stress_env: Any
) -> None:
    k = kit()
    db = scratch_db_factory()
    before = snapshot(db)
    version_before = k.fetchval(db.admin_dsn, "SELECT version_num FROM alembic_version")
    assert _app_role_has_grants(before), "the migration granted the app role nothing"

    proc = k.alembic(stress_env, db, "upgrade", "head")
    returncode, stderr = proc.returncode, proc.stderr

    assert returncode == 0, f"alembic upgrade head failed on a migrated database: {stderr[-800:]}"
    version_after = k.fetchval(db.admin_dsn, "SELECT version_num FROM alembic_version")
    after = snapshot(db)
    assert version_after == version_before
    assert after == before


@pytest.mark.integration
@pytest.mark.parametrize("drift_sql", list(OWNER_DRIFT.values()), ids=list(OWNER_DRIFT))
def test_owner_drift_is_healed(scratch_db_factory: Callable[..., Any], drift_sql: str) -> None:
    k = kit()
    mg = k.lazy(MG)
    db = scratch_db_factory()
    grants = table_grants()
    original = snapshot(db)

    k.execute(db.admin_dsn, drift_sql)
    drifted = snapshot(db)
    assert drifted != original, "the drift statement changed nothing; the test proves nothing"

    _apply(db, mg, grants)

    healed = snapshot(db)
    assert healed == original
    _verify(db, mg, grants)


@pytest.mark.integration
def test_third_grantor_drift_is_detected(
    scratch_db_factory: Callable[..., Any], scratch_manager: Any
) -> None:
    k = kit()
    mg = k.lazy(MG)
    db = scratch_db_factory()
    grants = table_grants()
    _verify(db, mg, grants)  # control: a freshly migrated database verifies clean

    third, third_pw = scratch_manager.new_role(db)
    k.execute(db.admin_dsn, f'GRANT UPDATE ON ledger_entries TO "{third}" WITH GRANT OPTION')
    third_dsn = k.to_dsn(k.with_user(db.admin_url, third, third_pw))
    k.execute(third_dsn, 'GRANT UPDATE ON ledger_entries TO "vulnscope_app"')

    _apply(db, mg, grants)  # the owner's REVOKE cannot remove a privilege granted by another grantor

    with pytest.raises(mg.MigrationPreconditionError):
        _verify(db, mg, grants)


@pytest.mark.integration
def test_app_role_member_of_migrator_is_rejected(
    scratch_db_factory: Callable[..., Any], scratch_manager: Any, stress_env: Any
) -> None:
    # A scratch role stands in for the app role: making the real, cluster-global vulnscope_app a
    # member of the migrator would leak into every other session on the cluster.
    k = kit()
    mg = k.lazy(MG)
    db = scratch_db_factory()
    member, _ = scratch_manager.new_role(db)
    migrator = stress_env.admin_user
    k.execute(db.admin_dsn, f'GRANT "{migrator}" TO "{member}"')

    with pytest.raises(mg.MigrationPreconditionError, match="member of"):
        k.run_sync_helper(db.admin_url, lambda c: mg.require_app_role(c, member))
