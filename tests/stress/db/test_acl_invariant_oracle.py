# ruff: noqa: E501
"""Stress #1: independent ACL oracle (plan 3.10.1). R1.

Policy comes from stress_db_oracle (hand-written invariants + Base.metadata); this module
imports nothing from vulnscope.db. Runs against a migrated scratch DB, or read-only against the
shared dev DB with VULNSCOPE_ORACLE_SHARED=1 (dry-run mode). The audited role is the real
``vulnscope_app``; the oracle reads catalogs through the migrator connection by role NAME.
"""
from __future__ import annotations

from typing import Any

import pytest
import stress_db_oracle as oracle
import vulnscope_db_plugin as kit

pytestmark = pytest.mark.integration
APP = "vulnscope_app"


def _violations(dsn: str, tags: tuple[str, ...] | None = None, table: str | None = None) -> list[str]:
    async def go(conn: Any) -> Any:
        await conn.execute("SET default_transaction_read_only = on")
        return await oracle.violations(conn, APP)

    found: list[str] = kit.with_conn(dsn, go)
    if tags:
        found = [v for v in found if v.split(":", 1)[0] in tags]
    if table:
        found = [v for v in found if f": {table}:" in v or v.endswith(f" {table}")]
    return found


def test_oracle_server_is_pg17_for_maintain(oracle_dsn: str) -> None:
    ver = kit.fetchval(oracle_dsn, "SELECT current_setting('server_version_num')::int")
    assert ver >= 170000, f"PG17 required so that MAINTAIN is checked; server_version_num={ver}"


def test_every_relation_has_a_grant_decision_and_every_metadata_table_exists(oracle_dsn: str) -> None:
    found = _violations(oracle_dsn, tags=("NO-DECISION", "MISSING-TABLE", "SEQUENCE"))
    assert not found, "relations without a grant decision or missing tables: " + "; ".join(found)


@pytest.mark.parametrize("table", oracle.ALL_TABLES)
def test_effective_table_privileges_are_exactly_the_policy(oracle_dsn: str, table: str) -> None:
    found = _violations(oracle_dsn, tags=("UNEXPECTED", "MISSING"), table=table)
    assert not found, f"effective table privileges of {APP} on {table} differ from policy: " + "; ".join(found)


@pytest.mark.parametrize("table", oracle.ALL_TABLES)
def test_any_column_privileges_agree_with_the_policy(oracle_dsn: str, table: str) -> None:
    found = _violations(oracle_dsn, tags=("COLUMN",), table=table)
    assert not found, f"column-level privileges of {APP} on {table} disagree with policy: " + "; ".join(found)


def test_no_column_acl_anywhere(oracle_dsn: str) -> None:
    found = _violations(oracle_dsn, tags=("COLUMN-ACL",))
    assert not found, "column ACLs present: " + "; ".join(found)


def test_relacl_has_no_public_no_foreign_grantee_no_foreign_grantor_no_grant_option(oracle_dsn: str) -> None:
    found = _violations(oracle_dsn, tags=("GRANTEE", "GRANTOR", "GRANT-OPTION"))
    assert not found, "relacl violations: " + "; ".join(found)


def test_app_role_does_not_own_or_inherit_the_table_owner(oracle_dsn: str) -> None:
    found = _violations(oracle_dsn, tags=("OWNER-IS-ROLE", "INHERITS-OWNER"))
    assert not found, "ownership violations: " + "; ".join(found)


def test_app_role_is_a_plain_login_role_with_no_memberships_and_no_create(oracle_dsn: str) -> None:
    found = _violations(
        oracle_dsn, tags=("ATTRIBUTE", "MEMBER-OF", "OWNS", "SCHEMA-CREATE", "DB-CREATE")
    )
    assert not found, "role-level violations: " + "; ".join(found)
