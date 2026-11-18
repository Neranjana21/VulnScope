# ruff: noqa: E501
"""Stress #6: a migrator session whose first search_path schema is not ``public``. R1.

The migration's create_table calls are unqualified while every GRANT is ``public.<table>``
(plan 3.10.1, INFRA-7). With a trap schema first, the tables would land in the trap schema:
the migration must fail closed (full rollback, nothing left in ANY schema), not succeed.
The search_path is set with ALTER DATABASE on the scratch DB only (never ALTER ROLE: roles are
cluster-global).
"""
from __future__ import annotations

from collections.abc import Callable

import pytest
import vulnscope_db_plugin as kit

pytestmark = pytest.mark.integration


def test_non_public_first_search_path_fails_closed_with_no_objects_anywhere(
    scratch_db_factory: Callable[..., kit.ScratchDb], stress_env: kit.StressEnv
) -> None:
    db = scratch_db_factory(migrate=False)
    kit.execute(
        db.admin_dsn,
        "CREATE SCHEMA trap",
        f'ALTER DATABASE "{db.name}" SET search_path = trap, public',
    )
    proc = kit.alembic(stress_env, db, "upgrade", "head")
    leftovers = [t for t in kit.user_tables(db) if t != "trap.alembic_version"]
    assert proc.returncode != 0, (
        "SEARCH-PATH TRAP: migration succeeded although the first search_path schema is 'trap'; "
        f"objects now present: {leftovers}"
    )
    assert not leftovers, f"SEARCH-PATH TRAP: objects left behind after the failed migration: {leftovers}"
    if "trap.alembic_version" in kit.user_tables(db):
        n = kit.fetchval(db.admin_dsn, "SELECT count(*) FROM trap.alembic_version")
        assert n == 0, f"SEARCH-PATH TRAP: alembic_version row left in trap schema ({n})"
    assert not [t for t in kit.user_tables(db) if t.startswith("public.")], (
        "SEARCH-PATH TRAP: objects appeared in public after a failed migration"
    )
