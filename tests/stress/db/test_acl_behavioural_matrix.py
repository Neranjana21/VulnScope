# ruff: noqa: E501
"""Stress #2 (GR-STR-11): behavioural ACL matrix, relation x verb, run AS the real vulnscope_app.

Every statement runs in a transaction that is always rolled back (``WHERE false``,
``DEFAULT VALUES``): no data is written. A superuser connection is never used for the probe,
because it would mask every result. Observed (denied/allowed) must equal both
``has_table_privilege`` and the hand-written invariants of stress_db_oracle.
"""
from __future__ import annotations

import itertools

import asyncpg
import pytest
import stress_db_oracle as oracle
import vulnscope_db_plugin as kit

pytestmark = pytest.mark.integration

CASES = list(itertools.product(oracle.ALL_TABLES, oracle.VERBS))


def _columns(admin_dsn: str, table: str) -> list[str]:
    rows = kit.fetch(
        admin_dsn,
        "SELECT attname FROM pg_attribute WHERE attrelid = ('public.' || quote_ident($1))::regclass "
        "AND attnum > 0 AND NOT attisdropped ORDER BY attnum",
        table,
    )
    return [r["attname"] for r in rows]


@pytest.mark.parametrize(("table", "verb"), CASES, ids=[f"{t}-{v}" for t, v in CASES])
def test_statement_outcome_equals_policy_and_has_table_privilege(
    migrated_scratch: kit.ScratchDb, table: str, verb: str
) -> None:
    db = migrated_scratch
    stmt = oracle.probe_statement(table, verb, _columns(db.admin_dsn, table))

    async def go(conn: asyncpg.Connection) -> tuple[str, str, str, bool]:
        who = await conn.fetchrow("SELECT current_user::text AS u")
        priv = "UPDATE" if verb == "SELECT_FOR_UPDATE" else verb
        has = await conn.fetchval(
            "SELECT has_table_privilege(current_user, ('public.' || quote_ident($1))::regclass, $2)",
            table,
            priv,
        )
        state, detail = await oracle.run_probe(conn, stmt)
        return who["u"], state, detail, bool(has)

    who, state, detail, has = kit.with_conn(db.app_dsn, go)
    assert who == "vulnscope_app", f"probe must run as vulnscope_app, ran as {who}"
    assert state != "unexpected", f"probe {stmt!r} failed for a non-privilege reason: {detail}"
    want = oracle.expected_verb_allowed(table, verb)
    observed = state == "allowed"
    assert observed == want, (
        f"BEHAVIOUR MISMATCH {table} {verb}: statement {'allowed' if observed else 'denied'} "
        f"({detail or 'ok'}), policy says {'allow' if want else 'deny'}"
    )
    assert has == want, f"has_table_privilege({verb}) = {has} disagrees with policy {want} on {table}"
