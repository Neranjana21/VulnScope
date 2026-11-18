# ruff: noqa: E501
"""Stress #8: escalation probes AS the real vulnscope_app on a migrated scratch DB. R1.

Every probe runs in a transaction that is rolled back. Each must be denied with
InsufficientPrivilegeError unless the independent policy says the verb is allowed (then it must
be allowed). ``CREATE TEMP TABLE`` is documented, not asserted either way.

Known and accepted (plan 3.10.1 residuals, GR-SEC-9): with UPDATE on chain_heads the app role may
take ACCESS EXCLUSIVE locks on it (a denial-of-service vector); the LOCK probe encodes the policy
as written (allowed exactly where UPDATE or DELETE is granted) so the behaviour is pinned.
Not probed (would persist cluster-global state): ``ALTER ROLE vulnscope_app SET ...``, which an
ordinary role may be allowed to run on itself; flagged in the post-gate as an open question.
"""
from __future__ import annotations

import asyncpg
import pytest
import stress_db_oracle as oracle
import vulnscope_db_plugin as kit

pytestmark = pytest.mark.integration

ROLE_LEVEL = {
    "set_role_migrator": "SET ROLE vulnscope_migrator",
    "copy_to_program": "COPY (SELECT 1) TO PROGRAM 'true'",
    "create_table_public": "CREATE TABLE public.stress_probe_x (a int)",
    "create_schema": "CREATE SCHEMA stress_probe_s",
    "select_pg_authid": "SELECT rolname FROM pg_authid LIMIT 1",
    "pg_read_file": "SELECT pg_read_file('/etc/hostname')",
    "lo_import": "SELECT lo_import('/etc/hostname')",
    "create_function": "CREATE FUNCTION public.stress_probe_f() RETURNS int LANGUAGE sql AS 'SELECT 1'",
    "drop_table_orgs": "DROP TABLE public.orgs",
}


def _probe(db: kit.ScratchDb, stmt: str) -> tuple[str, str]:
    async def go(conn: asyncpg.Connection) -> tuple[str, str, str]:
        who = await conn.fetchval("SELECT current_user::text")
        state, detail = await oracle.run_probe(conn, stmt)
        return who, state, detail

    who, state, detail = kit.with_conn(db.app_dsn, go)
    assert who == "vulnscope_app", f"probe ran as {who}, not vulnscope_app"
    return state, detail


@pytest.mark.parametrize("stmt", ROLE_LEVEL.values(), ids=list(ROLE_LEVEL))
def test_role_level_probe_is_denied(migrated_scratch: kit.ScratchDb, stmt: str) -> None:
    state, detail = _probe(migrated_scratch, stmt)
    assert state == "denied", f"ESCALATION: {stmt!r} was {state} ({detail})"


@pytest.mark.parametrize("table", oracle.ALL_TABLES)
def test_truncate_is_denied_on_every_table(migrated_scratch: kit.ScratchDb, table: str) -> None:
    state, detail = _probe(migrated_scratch, f'TRUNCATE public."{table}"')
    assert state == "denied", f"ESCALATION: TRUNCATE {table} was {state} ({detail})"


@pytest.mark.parametrize("table", oracle.ALL_TABLES)
def test_unqualified_delete_follows_policy_on_every_table(
    migrated_scratch: kit.ScratchDb, table: str
) -> None:
    state, detail = _probe(migrated_scratch, f'DELETE FROM public."{table}"')
    assert state != "unexpected", f"DELETE {table}: unexpected error {detail}"
    want = oracle.expected_verb_allowed(table, "DELETE")
    assert (state == "allowed") == want, (
        f"DELETE-POLICY {table}: statement {state}, policy says {'allow' if want else 'deny'}"
    )


@pytest.mark.parametrize("table", oracle.ALL_TABLES)
def test_lock_access_exclusive_follows_policy_on_every_table(
    migrated_scratch: kit.ScratchDb, table: str
) -> None:
    state, detail = _probe(migrated_scratch, f'LOCK TABLE public."{table}" IN ACCESS EXCLUSIVE MODE')
    assert state != "unexpected", f"LOCK {table}: unexpected error {detail}"
    privs = oracle.expected_privileges(table)
    want = bool(privs & {"UPDATE", "DELETE"})
    assert (state == "allowed") == want, (
        f"LOCK-POLICY {table}: ACCESS EXCLUSIVE {state}, policy says {'allow' if want else 'deny'}"
    )


@pytest.mark.parametrize("table", ["ledger_entries", "checkpoints", "chain_heads", "orgs"])
def test_disabling_triggers_needs_ownership_and_is_denied(
    migrated_scratch: kit.ScratchDb, table: str
) -> None:
    state, detail = _probe(migrated_scratch, f'ALTER TABLE public."{table}" DISABLE TRIGGER ALL')
    assert state == "denied", f"ESCALATION: DISABLE TRIGGER on {table} was {state} ({detail})"


def test_create_temp_table_outcome_is_documented(migrated_scratch: kit.ScratchDb) -> None:
    state, detail = _probe(migrated_scratch, "CREATE TEMP TABLE stress_probe_tmp (a int)")
    kit.record("probe", {"stmt": "CREATE TEMP TABLE", "state": state, "detail": detail})
    assert state in ("allowed", "denied"), f"unexpected error class for TEMP: {detail}"
