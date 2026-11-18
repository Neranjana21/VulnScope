# ruff: noqa: E501
"""Stress #4 (GR-SEC-1, GR-STR-10): role-name and CLI abuse. R1.

* grant_statements / require_app_role are fed hostile identifiers and over-powered roles.
* ``alembic -x app_role=...`` must be ignored: the real vulnscope_app gets the grants, the named
  role gains nothing (there is no -x seam; plan 3.10.1).
Hostile-input tests need no database (not integration-marked); the lazy import makes each one
fail on its own before the fix.
"""
from __future__ import annotations

from collections.abc import Callable

import pytest
import stress_db_oracle as oracle
import vulnscope_db_plugin as kit

HOSTILE_ROLES = {
    "double_quote": 'a"b',
    "semicolon": "x; DROP TABLE orgs",
    "uppercase": "VulnScope_App",
    "leading_space": " vulnscope_app",
    "trailing_newline": "vulnscope_app\n",
    "nul": "vuln\x00scope",
    "len_64": "a" * 64,
    "empty": "",
    "dollar_quote": "$$x$$",
    "unicode": "vulnscöpe",
}
HOSTILE_PRIVS = {
    "injection": ("SELECT; DROP TABLE x",),
    "truncate": ("TRUNCATE",),
    "all": ("ALL",),
    "references": ("REFERENCES",),
    "lowercase": ("select",),
    "duplicate": ("SELECT", "SELECT"),
    "trigger": ("TRIGGER",),
    "maintain": ("MAINTAIN",),
}


@pytest.mark.parametrize("bad", HOSTILE_ROLES.values(), ids=list(HOSTILE_ROLES))
def test_grant_statements_rejects_hostile_role_names(bad: str) -> None:
    mg = kit.lazy("vulnscope.db.migration_grants")
    with pytest.raises(mg.MigrationPreconditionError):
        mg.grant_statements(bad, oracle.expected_map())


@pytest.mark.parametrize("bad", ['a"b', "Orgs", "x;y", "t\x00", "t" * 64, "", "orgs\n"], ids=[
    "quote", "uppercase", "semicolon", "nul", "len_64", "empty", "newline"])
def test_grant_statements_rejects_hostile_table_names(bad: str) -> None:
    mg = kit.lazy("vulnscope.db.migration_grants")
    table_map = {**oracle.expected_map(), bad: ("SELECT",)}
    with pytest.raises(mg.MigrationPreconditionError):
        mg.grant_statements(mg.APP_ROLE, table_map)


@pytest.mark.parametrize("privs", HOSTILE_PRIVS.values(), ids=list(HOSTILE_PRIVS))
def test_grant_statements_rejects_hostile_privileges(privs: tuple[str, ...]) -> None:
    mg = kit.lazy("vulnscope.db.migration_grants")
    table_map = {**oracle.expected_map(), "orgs": privs}
    with pytest.raises(mg.MigrationPreconditionError):
        mg.grant_statements(mg.APP_ROLE, table_map)


@pytest.mark.parametrize("table", ["ledger_entries", "checkpoints", "chain_heads", "alembic_version"])
def test_fixed_privileges_cannot_be_widened_by_a_map(table: str) -> None:
    mg = kit.lazy("vulnscope.db.migration_grants")
    table_map = {**oracle.expected_map(), table: ("SELECT", "INSERT", "UPDATE", "DELETE")}
    with pytest.raises(mg.MigrationPreconditionError):
        mg.grant_statements(mg.APP_ROLE, table_map)


def test_grant_statements_requires_explicit_alembic_version_decision() -> None:
    mg = kit.lazy("vulnscope.db.migration_grants")
    table_map = {k: v for k, v in oracle.expected_map().items() if k != "alembic_version"}
    with pytest.raises(mg.MigrationPreconditionError):
        mg.grant_statements(mg.APP_ROLE, table_map)


# ---------------------------------------------------------------- require_app_role against real roles
pytestmark_db = pytest.mark.integration

ROLE_CASES = {
    "bypassrls": "ALTER ROLE \"{r}\" BYPASSRLS",
    "createdb": 'ALTER ROLE "{r}" CREATEDB',
    "createrole": 'ALTER ROLE "{r}" CREATEROLE',
    "replication": 'ALTER ROLE "{r}" REPLICATION',
    "nologin": 'ALTER ROLE "{r}" NOLOGIN',
    "superuser": 'ALTER ROLE "{r}" SUPERUSER',
}


@pytestmark_db
@pytest.mark.parametrize("sql", ROLE_CASES.values(), ids=list(ROLE_CASES))
def test_require_app_role_rejects_overpowered_roles(
    migrated_scratch: kit.ScratchDb, scratch_manager: kit.ScratchManager,
    stress_env: kit.StressEnv, sql: str,
) -> None:
    if not stress_env.admin_is_superuser:
        pytest.skip("needs a superuser migrator to create such roles")
    mg = kit.lazy("vulnscope.db.migration_grants")
    role, _ = scratch_manager.new_role(migrated_scratch)
    try:
        kit.execute(migrated_scratch.admin_dsn, sql.format(r=role))
        with pytest.raises(mg.MigrationPreconditionError):
            kit.run_sync_helper(migrated_scratch.admin_url, lambda c: mg.require_app_role(c, role))
    finally:
        scratch_manager.drop_role(migrated_scratch, role)


@pytestmark_db
def test_require_app_role_rejects_the_migrator_itself(
    migrated_scratch: kit.ScratchDb, stress_env: kit.StressEnv
) -> None:
    mg = kit.lazy("vulnscope.db.migration_grants")
    with pytest.raises(mg.MigrationPreconditionError):
        kit.run_sync_helper(
            migrated_scratch.admin_url, lambda c: mg.require_app_role(c, stress_env.admin_user)
        )


@pytestmark_db
def test_require_app_role_accepts_a_plain_login_role_control(
    migrated_scratch: kit.ScratchDb, scratch_manager: kit.ScratchManager
) -> None:
    mg = kit.lazy("vulnscope.db.migration_grants")
    role, _ = scratch_manager.new_role(migrated_scratch)
    try:
        kit.run_sync_helper(migrated_scratch.admin_url, lambda c: mg.require_app_role(c, role))
    finally:
        scratch_manager.drop_role(migrated_scratch, role)


# ---------------------------------------------------------------- the CLI -x seam must not exist
@pytestmark_db
@pytest.mark.parametrize("target", ["pg_read_all_data", "scratch_group"])
def test_cli_x_app_role_is_ignored_and_real_app_role_gets_the_grants(
    scratch_db_factory: Callable[..., kit.ScratchDb], stress_env: kit.StressEnv, scratch_manager: kit.ScratchManager, target: str
) -> None:
    db = scratch_db_factory(migrate=False)
    named = target
    if target == "scratch_group":
        named, _ = scratch_manager.new_role(db, login=False)
        member, _ = scratch_manager.new_role(db)
        kit.execute(db.admin_dsn, f'GRANT "{named}" TO "{member}"')
    proc = kit.alembic(stress_env, db, "-x", f"app_role={named}", "upgrade", "head")
    assert proc.returncode == 0, f"upgrade with -x failed: {proc.stderr[-800:]}"
    app_select = kit.fetchval(
        db.admin_dsn, "SELECT has_table_privilege('vulnscope_app', 'public.orgs', 'SELECT')"
    )
    assert app_select, "ABUSE: vulnscope_app did not receive its grants when -x app_role=... was passed"
    acl = kit.fetch(
        db.admin_dsn,
        "SELECT relname, relacl::text AS acl FROM pg_class WHERE relnamespace = 'public'::regnamespace "
        "AND relkind = 'r'",
    )
    leaked = [r["relname"] for r in acl if r["acl"] and f"{named}=" in r["acl"]]
    assert not leaked, f"ABUSE: -x app_role={named} gained privileges on {leaked}"
