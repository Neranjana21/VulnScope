# ruff: noqa: E501
"""Stress #15 (GR-SEC-3): cluster default privileges must not leak into new tables. R1.

Before migrating a fresh scratch DB, ``ALTER DEFAULT PRIVILEGES FOR ROLE <migrator> IN SCHEMA
public GRANT ALL ON TABLES TO ...`` makes every table the migration creates (including the
table Alembic itself creates, ``alembic_version``) start out with grants. pg_default_acl is per
database, so this stays inside the scratch DB. After the migration the oracle invariants must
hold on EVERY table.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
import stress_db_oracle as oracle
import vulnscope_db_plugin as kit

pytestmark = pytest.mark.integration

VARIANTS = {
    "public": 'PUBLIC',
    "app": '"vulnscope_app"',
    "public_and_app": 'PUBLIC, "vulnscope_app"',
}


@pytest.mark.parametrize("grantees", VARIANTS.values(), ids=list(VARIANTS))
def test_default_privileges_do_not_leak_into_migrated_tables(
    scratch_db_factory: Callable[..., kit.ScratchDb], stress_env: kit.StressEnv, grantees: str
) -> None:
    db = scratch_db_factory(migrate=False)
    kit.execute(
        db.admin_dsn,
        f'ALTER DEFAULT PRIVILEGES FOR ROLE "{stress_env.admin_user}" IN SCHEMA public '
        f"GRANT ALL ON TABLES TO {grantees}",
    )
    seeded = kit.fetchval(db.admin_dsn, "SELECT count(*) FROM pg_default_acl")
    assert seeded == 1, f"default-privilege seed not in place (pg_default_acl rows: {seeded})"
    proc = kit.alembic(stress_env, db, "upgrade", "head")
    assert proc.returncode == 0, f"migration failed under drifted defaults: {proc.stderr[-800:]}"

    async def go(conn: Any) -> Any:
        return await oracle.violations(conn, "vulnscope_app")

    found = kit.with_conn(db.admin_dsn, go)
    assert not found, (
        f"DEFAULT-PRIVILEGE LEAK: {len(found)} invariant violation(s) after migration; first: "
        + "; ".join(found[:6])
    )
    acl = kit.fetchval(
        db.admin_dsn, "SELECT coalesce(relacl::text, '-') FROM pg_class WHERE oid = 'public.alembic_version'::regclass"
    )
    assert "vulnscope_app=" not in acl and "{=" not in acl and ",=" not in acl, (
        f"DEFAULT-PRIVILEGE LEAK: alembic_version relacl = {acl}"
    )
