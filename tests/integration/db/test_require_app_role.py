# ruff: noqa: E501
"""L6 (docs/gates/slice0-plan.md 3.10.1): ``require_app_role(conn, role)`` refuses, with a
``MigrationPreconditionError`` and before any DDL (the relation set is unchanged), every role
that is not the least-privilege application role, and accepts a plain one.

One migrated scratch database per module; every scratch role and object is removed in
``finally``. Cases that need a superuser to create the role skip loudly when the migrator is not
one (a skip is a failure under VULNSCOPE_REQUIRE_INTEGRATION=1, so the dev run, where the
migrator is the bootstrap superuser, is the one that counts).
"""
from __future__ import annotations

import secrets
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

_INTEGRATION_DIR = Path(__file__).resolve().parents[1]
if str(_INTEGRATION_DIR) not in sys.path:
    sys.path.insert(0, str(_INTEGRATION_DIR))

from _dbkit import kit  # noqa: E402

MG = "vulnscope.db.migration_grants"


@dataclass(frozen=True)
class Case:
    setup: tuple[str, ...] = ()  # {r} = the role under test, {db} = the scratch database, {m} = migrator
    needs_superuser: bool = False
    member_of_scratch_group: bool = False
    cleanup: tuple[str, ...] = ()  # run (best effort) before the role is dropped


CASES: dict[str, Case] = {
    "nonexistent_role": Case(),
    "migrator_itself": Case(),
    "attr_bypassrls": Case(('ALTER ROLE "{r}" BYPASSRLS',), needs_superuser=True),
    "attr_createrole": Case(('ALTER ROLE "{r}" CREATEROLE',)),
    "attr_createdb": Case(('ALTER ROLE "{r}" CREATEDB',)),
    "attr_replication": Case(('ALTER ROLE "{r}" REPLICATION',), needs_superuser=True),
    "attr_nologin": Case(('ALTER ROLE "{r}" NOLOGIN',)),
    "member_of_migrator": Case(('GRANT "{m}" TO "{r}"',)),
    "member_pg_read_all_data": Case(('GRANT pg_read_all_data TO "{r}"',), needs_superuser=True),
    "member_pg_write_all_data": Case(('GRANT pg_write_all_data TO "{r}"',), needs_superuser=True),
    "member_pg_execute_server_program": Case(('GRANT pg_execute_server_program TO "{r}"',), needs_superuser=True),
    "member_pg_read_server_files": Case(('GRANT pg_read_server_files TO "{r}"',), needs_superuser=True),
    "member_pg_write_server_files": Case(('GRANT pg_write_server_files TO "{r}"',), needs_superuser=True),
    "member_pg_signal_backend": Case(('GRANT pg_signal_backend TO "{r}"',), needs_superuser=True),
    "member_pg_maintain": Case(('GRANT pg_maintain TO "{r}"',), needs_superuser=True),
    "member_of_scratch_group": Case(member_of_scratch_group=True),
    "owns_table": Case(
        ('CREATE TABLE public.vs_l6_owned (id integer)', 'ALTER TABLE public.vs_l6_owned OWNER TO "{r}"'),
        cleanup=("DROP TABLE IF EXISTS public.vs_l6_owned",),
    ),
    "owns_schema": Case(
        ('CREATE SCHEMA vs_l6_owned AUTHORIZATION "{r}"',),
        cleanup=("DROP SCHEMA IF EXISTS vs_l6_owned CASCADE",),
    ),
    "create_on_schema_public": Case(('GRANT CREATE ON SCHEMA public TO "{r}"',)),
    "create_on_database": Case(('GRANT CREATE ON DATABASE "{db}" TO "{r}"',)),
}


@pytest.mark.integration
@pytest.mark.parametrize("case_id", list(CASES))
def test_require_app_role_rejects(
    case_id: str, migrated_scratch: Any, scratch_manager: Any, stress_env: Any
) -> None:
    case = CASES[case_id]
    if case.needs_superuser and not stress_env.admin_is_superuser:
        pytest.skip("needs a superuser migrator to create such a role")
    k = kit()
    mg = k.lazy(MG)
    db = migrated_scratch
    relations_before = k.user_tables(db)
    created: list[str] = []
    try:
        if case_id == "nonexistent_role":
            role = f"vtest_missing_{secrets.token_hex(4)}"
        elif case_id == "migrator_itself":
            role = stress_env.admin_user
        else:
            role, _ = scratch_manager.new_role(db)
            created.append(role)
            if case.member_of_scratch_group:
                group, _ = scratch_manager.new_role(db, login=False)
                created.append(group)
                k.execute(db.admin_dsn, f'GRANT "{group}" TO "{role}"')
            for sql in case.setup:
                k.execute(db.admin_dsn, sql.format(r=role, db=db.name, m=stress_env.admin_user))

        with pytest.raises(mg.MigrationPreconditionError) as raised:
            k.run_sync_helper(db.admin_url, lambda c: mg.require_app_role(c, role))
        message = str(raised.value)
        if case_id == "nonexistent_role":
            assert role in message
            assert "not in pg_roles" in message
            assert "No DDL was applied" in message
    finally:
        for sql in case.cleanup:
            k.execute(db.admin_dsn, sql)
        for name in reversed(created):
            scratch_manager.drop_role(db, name)

    relations_after = k.user_tables(db)
    assert relations_after == relations_before, "require_app_role changed the relation set"


@pytest.mark.integration
def test_require_app_role_accepts_plain_login_role(migrated_scratch: Any, scratch_manager: Any) -> None:
    k = kit()
    mg = k.lazy(MG)
    db = migrated_scratch
    relations_before = k.user_tables(db)
    role, _ = scratch_manager.new_role(db)
    try:
        k.run_sync_helper(db.admin_url, lambda c: mg.require_app_role(c, role))
    finally:
        scratch_manager.drop_role(db, role)

    relations_after = k.user_tables(db)
    assert relations_after == relations_before
