# ruff: noqa: E501
"""Stress #9: idempotency and drift, independent re-implementation of plan L3/L4. R1.

Snapshot = every relation (r,p,v,m,S,f; all non-system schemas) with owner, relacl text
(grantors, grant options) and every column ACL. Drift is applied by the table owner (the
superuser migrator) to the REAL vulnscope_app inside a scratch DB (database-level ACLs only).
Healing is re-applying ``grant_statements(APP_ROLE, map)`` through ``apply_statements``; the map
fed to it comes from the independent oracle, not from the migration. Drift the helper cannot heal
(third grantor) must be REPORTED by ``verify_effective_privileges``.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
import stress_db_oracle as oracle
import vulnscope_db_plugin as kit

pytestmark = pytest.mark.integration

DRIFT = {
    "ledger_update_delete_truncate": ['GRANT UPDATE, DELETE, TRUNCATE ON public."ledger_entries" TO "vulnscope_app"'],
    "public_all_chain_heads": ['GRANT ALL ON public."chain_heads" TO PUBLIC'],
    "column_grant_ledger": ['GRANT UPDATE ("kind") ON public."ledger_entries" TO "vulnscope_app"'],
    "public_all_alembic_version": ['GRANT ALL ON public."alembic_version" TO PUBLIC'],
    "grant_option": ['GRANT SELECT ON public."orgs" TO "vulnscope_app" WITH GRANT OPTION'],
    "public_on_every_table": ["GRANT ALL ON ALL TABLES IN SCHEMA public TO PUBLIC"],
    "app_gets_all_on_every_table": ['GRANT ALL ON ALL TABLES IN SCHEMA public TO "vulnscope_app"'],
}


def _snapshot(db: kit.ScratchDb) -> list[tuple[str, ...]]:
    async def go(conn: Any) -> Any:
        return await oracle.snapshot(conn)

    return kit.with_conn(db.admin_dsn, go)


def _oracle(db: kit.ScratchDb) -> list[str]:
    async def go(conn: Any) -> Any:
        return await oracle.violations(conn, "vulnscope_app")

    return kit.with_conn(db.admin_dsn, go)


def _reapply(db: kit.ScratchDb) -> None:
    mg = kit.lazy("vulnscope.db.migration_grants")

    def fn(conn: Any) -> None:
        stmts = mg.grant_statements(mg.APP_ROLE, oracle.expected_map())
        mg.apply_statements(conn, stmts)

    kit.run_sync_helper(db.admin_url, fn)


def test_alembic_rerun_on_a_migrated_db_changes_nothing(
    scratch_db_factory: Callable[..., kit.ScratchDb], stress_env: kit.StressEnv
) -> None:
    db = scratch_db_factory(migrate=True)
    before = _snapshot(db)
    version_before = kit.fetchval(db.admin_dsn, "SELECT version_num FROM public.alembic_version")
    proc = kit.alembic(stress_env, db, "upgrade", "head")
    assert proc.returncode == 0, f"re-run failed: {proc.stderr[-600:]}"
    assert _snapshot(db) == before, "IDEMPOTENCY: ACL snapshot changed by a no-op upgrade"
    assert kit.fetchval(db.admin_dsn, "SELECT version_num FROM public.alembic_version") == version_before


def test_reapplying_the_helper_statements_twice_is_byte_identical(
    scratch_db_factory: Callable[..., kit.ScratchDb],
) -> None:
    db = scratch_db_factory(migrate=True)
    _reapply(db)
    first = _snapshot(db)
    _reapply(db)
    assert _snapshot(db) == first, "IDEMPOTENCY: second application changed the snapshot"
    assert _oracle(db) == [], "oracle violations after a clean re-application: " + "; ".join(_oracle(db)[:4])


@pytest.mark.parametrize("sql", DRIFT.values(), ids=list(DRIFT))
def test_owner_drift_is_healed_back_to_the_exact_original_snapshot(
    scratch_db_factory: Callable[..., kit.ScratchDb], sql: list[str]
) -> None:
    kit.lazy("vulnscope.db.migration_grants")  # red individually before the fix
    db = scratch_db_factory(migrate=True)
    original = _snapshot(db)
    kit.execute(db.admin_dsn, *sql)
    assert _snapshot(db) != original, "drift statement changed nothing; test setup is wrong"
    assert _oracle(db), "oracle did not see the drift before healing"
    _reapply(db)
    assert _snapshot(db) == original, "DRIFT NOT HEALED: snapshot differs from the original after re-application"
    assert _oracle(db) == [], "oracle still reports violations after healing"


def test_third_grantor_drift_cannot_be_healed_and_must_be_reported(
    scratch_db_factory: Callable[..., kit.ScratchDb], scratch_manager: kit.ScratchManager
) -> None:
    mg = kit.lazy("vulnscope.db.migration_grants")
    db = scratch_db_factory(migrate=True)
    g, _ = scratch_manager.new_role(db, login=False)
    kit.execute(
        db.admin_dsn,
        f'GRANT UPDATE ON public."ledger_entries" TO "{g}" WITH GRANT OPTION',
        f'SET ROLE "{g}"',
        'GRANT UPDATE ON public."ledger_entries" TO "vulnscope_app"',
        "RESET ROLE",
    )
    _reapply(db)
    assert any("UPDATE" in v for v in _oracle(db)), "oracle must still see the third-grantor UPDATE"
    with pytest.raises(mg.MigrationPreconditionError):
        kit.run_sync_helper(
            db.admin_url,
            lambda c: mg.verify_effective_privileges(c, mg.APP_ROLE, oracle.expected_map()),
        )


def test_alembic_rerun_does_not_heal_drift_but_the_oracle_still_reports_it(
    scratch_db_factory: Callable[..., kit.ScratchDb], stress_env: kit.StressEnv
) -> None:
    """Documented limit (plan: 'Note (c) does not heal drift'): Alembic skips 0001. Detection is the
    oracle's job."""
    db = scratch_db_factory(migrate=True)
    kit.execute(db.admin_dsn, 'GRANT UPDATE ON public."ledger_entries" TO "vulnscope_app"')
    drifted = _snapshot(db)
    proc = kit.alembic(stress_env, db, "upgrade", "head")
    assert proc.returncode == 0
    assert _snapshot(db) == drifted, "alembic re-run unexpectedly changed ACLs"
    found = _oracle(db)
    assert any("UNEXPECTED: ledger_entries: vulnscope_app has UPDATE" in v for v in found), (
        "oracle failed to report UPDATE drift on ledger_entries: " + "; ".join(found[:4])
    )
