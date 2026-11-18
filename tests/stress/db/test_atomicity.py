# ruff: noqa: E501
"""Stress #5 (GR-STR-19, GR-STR-26): migration 0001 is all-or-nothing. R1.

Failures are injected two ways, never by editing production code in the repo:
  * map faults: a temporary COPY of alembic/ whose literal ``TABLE_GRANTS`` is edited;
  * runtime faults: a child interpreter monkeypatches ``migration_grants`` helpers
    (apply_statements on the Nth statement, verify_effective_privileges) and runs alembic
    in-process.
After every failure: non-zero exit, the injected/expected error text present (so a failure for
the wrong reason, e.g. ModuleNotFoundError, is red), no user table left (``alembic_version``
may exist but must be empty), and the ACL snapshot unchanged.
"""
from __future__ import annotations

import re
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import stress_db_oracle as oracle
import vulnscope_db_plugin as kit

pytestmark = pytest.mark.integration
MIGRATION = kit.REPO_ROOT / "alembic" / "versions" / "0001_initial.py"


def _snapshot(db: kit.ScratchDb) -> list[tuple[str, ...]]:
    async def go(conn: Any) -> Any:
        return await oracle.snapshot(conn)

    return kit.with_conn(db.admin_dsn, go)


def _assert_rolled_back(db: kit.ScratchDb, before: list[tuple[str, ...]]) -> None:
    tables = [t for t in kit.user_tables(db) if t != "public.alembic_version"]
    assert not tables, f"ATOMICITY: user tables left after a failed migration: {tables}"
    if "public.alembic_version" in kit.user_tables(db):
        n = kit.fetchval(db.admin_dsn, "SELECT count(*) FROM public.alembic_version")
        assert n == 0, f"ATOMICITY: alembic_version has {n} row(s) after a failed migration"
    assert _snapshot(db) == before, "ATOMICITY: ACL snapshot changed by a failed migration"


def _copy_with_edited_map(tmp: Path, edit: str) -> Path:
    src = MIGRATION.read_text(encoding="utf-8")
    m = re.search(r"^TABLE_GRANTS[^=\n]*=\s*\{.*?^\}", src, re.DOTALL | re.MULTILINE)
    if m is None:
        pytest.fail("0001_initial.py has no module-level literal TABLE_GRANTS (plan 3.10.1 structure)")
    block = m.group(0)
    if edit == "omit_orgs":
        new = re.sub(r'^\s*"orgs":.*\n', "", block, flags=re.MULTILINE)
    elif edit == "ghost_table":
        new = block.replace("{", '{\n    "ghost_table": ("SELECT",),', 1)
    elif edit == "malformed_privs":
        new = re.sub(r'^(\s*)"orgs":.*$', r'\1"orgs": ("SELECT", "TRUNCATE"),', block, flags=re.MULTILINE)
    elif edit == "widen_ledger":
        new = re.sub(
            r'^(\s*)"ledger_entries":.*$',
            r'\1"ledger_entries": ("SELECT", "INSERT", "UPDATE", "DELETE"),',
            block,
            flags=re.MULTILINE,
        )
    else:
        raise KeyError(edit)
    assert new != block, f"edit {edit} did not change the map"
    root = tmp / "copy"
    shutil.copytree(kit.REPO_ROOT / "alembic", root / "alembic", ignore=shutil.ignore_patterns("__pycache__"))
    (root / "alembic" / "versions" / "0001_initial.py").write_text(
        src.replace(block, new), encoding="utf-8"
    )
    ini = (kit.REPO_ROOT / "alembic.ini").read_text(encoding="utf-8")
    ini = re.sub(r"^script_location\s*=.*$", f"script_location = {root / 'alembic'}", ini, flags=re.MULTILINE)
    (root / "alembic.ini").write_text(ini, encoding="utf-8")
    return root


@pytest.mark.parametrize("edit", ["omit_orgs", "ghost_table", "malformed_privs", "widen_ledger"])
def test_map_faults_roll_back_everything(
    scratch_db_factory: Callable[..., kit.ScratchDb], stress_env: kit.StressEnv, tmp_path: Path, edit: str
) -> None:
    db = scratch_db_factory(migrate=False)
    before = _snapshot(db)
    root = _copy_with_edited_map(tmp_path, edit)
    proc = kit.alembic(
        stress_env, db, "-c", str(root / "alembic.ini"), "upgrade", "head", cwd=root,
        extra_env={"PYTHONPATH": str(kit.REPO_ROOT / "src")},
    )
    assert proc.returncode != 0, f"a faulty grant map ({edit}) must fail the migration"
    assert "MigrationPreconditionError" in proc.stderr, (
        f"map fault {edit} failed for the wrong reason (expected MigrationPreconditionError): "
        f"{proc.stderr[-600:]}"
    )
    _assert_rolled_back(db, before)


INJECT_APPLY = """
_orig = mg.apply_statements
def _boom(conn, statements):
    n = {n} if {n} >= 0 else len(statements) - 1
    for i, s in enumerate(statements):
        if i == n:
            raise RuntimeError("INJECTED_FAILURE_AT_%d" % i)
        _orig(conn, [s])
mg.apply_statements = _boom
"""
INJECT_VERIFY = """
def _bad(*a, **k):
    raise RuntimeError("INJECTED_VERIFY_FAILURE")
mg.verify_effective_privileges = _bad
"""


@pytest.mark.parametrize("n", [0, 1, 5, -1], ids=["stmt0", "stmt1", "stmt5", "last_stmt"])
def test_failure_on_nth_grant_statement_rolls_back_everything(
    scratch_db_factory: Callable[..., kit.ScratchDb], stress_env: kit.StressEnv, n: int
) -> None:
    db = scratch_db_factory(migrate=False)
    before = _snapshot(db)
    proc = kit.alembic_patched(stress_env, db, INJECT_APPLY.format(n=n), "upgrade", "head")
    assert proc.returncode != 0
    assert "INJECTED_FAILURE_AT_" in proc.stderr, (
        "the injected failure never fired (the patched helper did not run); stderr tail: "
        + proc.stderr[-500:]
    )
    _assert_rolled_back(db, before)


def test_failing_verify_effective_privileges_rolls_back_everything(
    scratch_db_factory: Callable[..., kit.ScratchDb], stress_env: kit.StressEnv
) -> None:
    db = scratch_db_factory(migrate=False)
    before = _snapshot(db)
    proc = kit.alembic_patched(stress_env, db, INJECT_VERIFY, "upgrade", "head")
    assert proc.returncode != 0
    assert "INJECTED_VERIFY_FAILURE" in proc.stderr, (
        "the injected verify failure never fired; stderr tail: " + proc.stderr[-500:]
    )
    _assert_rolled_back(db, before)


def test_unpatched_wrapper_control_succeeds_and_is_policy_clean(
    scratch_db_factory: Callable[..., kit.ScratchDb], stress_env: kit.StressEnv
) -> None:
    """Control for the two tests above: the same child-interpreter route with no fault succeeds, so
    the failures above are caused by the injection and not by the wrapper."""
    db = scratch_db_factory(migrate=False)
    proc = kit.alembic_patched(stress_env, db, "pass", "upgrade", "head")
    assert proc.returncode == 0, f"control run failed: {proc.stderr[-600:]}"

    async def go(conn: Any) -> Any:
        return await oracle.violations(conn, "vulnscope_app")

    found = kit.with_conn(db.admin_dsn, go)
    assert not found, "control run left policy violations: " + "; ".join(found[:5])

