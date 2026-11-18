# ruff: noqa: E501
"""Small shared helpers for the grants integration tests (docs/gates/slice0-plan.md 3.10.1).

Plain helper module (no ``test_`` prefix), loaded by sys.path insertion exactly like
``_guard.py``. It owns no scratch-database, guard, lock or skip logic: those come from the R1
plugin's fixtures (``scratch_db_factory``, ``migrated_scratch``, ``shared_db_lock``,
``stress_env``). It only reaches the plugin *lazily*, inside function bodies, so collecting
``tests/integration`` never fails when the plugin is not registered.

Secret hygiene: nothing here returns, raises with, or logs a DSN, URL or password. Test
assertions must be written over the plain values these helpers return, never over a
``ScratchDb``/``StressEnv`` object or a DSN string, because pytest prints the operands of a
failed assertion.
"""
from __future__ import annotations

import ast
import importlib
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
MIGRATION_0001 = REPO_ROOT / "alembic" / "versions" / "0001_initial.py"

SNAPSHOT_SQL = """
SELECT n.nspname::text AS s, c.relname::text AS n, c.relkind::text AS k,
       pg_catalog.pg_get_userbyid(c.relowner)::text AS owner,
       coalesce(c.relacl::text, '') AS relacl,
       coalesce((SELECT string_agg(
                    pg_catalog.pg_get_userbyid(a.grantor) || '>' ||
                    CASE WHEN a.grantee = 0 THEN 'PUBLIC'
                         ELSE pg_catalog.pg_get_userbyid(a.grantee) END || ':' ||
                    a.privilege_type || ':' || a.is_grantable::text, ',' ORDER BY
                    pg_catalog.pg_get_userbyid(a.grantor), a.grantee, a.privilege_type)
                 FROM pg_catalog.aclexplode(c.relacl) a), '') AS acl,
       coalesce((SELECT string_agg(att.attname::text || '=' || att.attacl::text, ',' ORDER BY att.attname)
                 FROM pg_catalog.pg_attribute att
                 WHERE att.attrelid = c.oid AND att.attacl IS NOT NULL), '') AS colacl
FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r','p','v','m','S','f')
  AND n.nspname NOT IN ('pg_catalog','information_schema')
  AND n.nspname NOT LIKE 'pg\\_toast%' AND n.nspname NOT LIKE 'pg\\_temp\\_%'
ORDER BY 1, 2
"""


def kit() -> Any:
    """The R1 plugin module (already imported by pytest when the plugin is registered)."""
    return importlib.import_module("vulnscope_db_plugin")


def table_grants() -> dict[str, tuple[str, ...]]:
    """The module-level literal ``TABLE_GRANTS`` of migration 0001, read without importing it."""
    tree = ast.parse(MIGRATION_0001.read_text(encoding="utf-8"))
    for node in tree.body:
        targets: list[ast.expr] = []
        value: ast.expr | None = None
        if isinstance(node, ast.Assign):
            targets, value = list(node.targets), node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets, value = [node.target], node.value
        if value is not None and any(isinstance(t, ast.Name) and t.id == "TABLE_GRANTS" for t in targets):
            literal = ast.literal_eval(value)
            assert isinstance(literal, dict), "TABLE_GRANTS is not a dict literal"
            return {str(k): tuple(v) for k, v in literal.items()}
    raise AssertionError("0001_initial.py has no module-level literal TABLE_GRANTS")


def snapshot(db: Any) -> list[tuple[str, ...]]:
    """Full ACL snapshot of one scratch database (owner, relacl, aclexplode with grantor and
    grant option, every column ACL) for relkinds r,p,v,m,S,f in all non-system schemas."""
    rows = kit().fetch(db.admin_dsn, SNAPSHOT_SQL)
    return [tuple(str(v) for v in r.values()) for r in rows]


def insert_ledger_row(db: Any) -> None:
    """One ledger row, inserted by the table owner (the migrator) into a scratch database."""
    kit().execute(
        db.admin_dsn,
        "INSERT INTO ledger_entries (id, schema_version, chain_id, seq, kind, actor, payload, ts, "
        "prev_hash, record_hash) VALUES (gen_random_uuid()::text, 1, 'engagement:downgrade-guard', 0, "
        "'policy.decision', 'system', '{}'::json, now(), repeat('a', 64), repeat('b', 64))",
    )
