# ruff: noqa: E501
"""Stress #14 (GR-STR-26): mutate the generated statements; the in-migration verification must
catch every mutant. R1.

A child interpreter monkeypatches ``migration_grants.grant_statements`` to DROP exactly one
statement (each REVOKE, the GRANT) for representative tables, then runs ``alembic upgrade head``
in-process on a scratch DB that was seeded with cluster-style default privileges
(``ALTER DEFAULT PRIVILEGES ... GRANT ALL ON TABLES TO PUBLIC, vulnscope_app``), so every
dropped statement leaves a detectable privilege behind. Expected for every mutant:
non-zero exit with ``MigrationPreconditionError`` in stderr (the wrong-reason
ModuleNotFoundError is red), no user table, no ``alembic_version`` row. The un-mutated control
must succeed and be oracle-clean. "#1 red" in the plan means: with verification bypassed the
oracle would see the drift; that variant is covered by test_oracle_detects_seeded_drift_when_verification_is_bypassed.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
import stress_db_oracle as oracle
import vulnscope_db_plugin as kit

pytestmark = pytest.mark.integration

PATCH = r"""
import re
_orig = mg.grant_statements
_pat = re.compile({pattern!r})
def _g(role, m):
    out = _orig(role, m)
    kept = [s for s in out if not _pat.fullmatch(s)]
    assert len(kept) == len(out) - 1, "MUTANT matched %d statements" % (len(out) - len(kept))
    return kept
mg.grant_statements = _g
"""
BYPASS_VERIFY = "mg.verify_effective_privileges = lambda *a, **k: None\n"


def _mutants() -> list[tuple[str, str]]:
    out = []
    for t in ("ledger_entries", "chain_heads", "orgs", "alembic_version"):
        q = rf'"public"\."{t}"'
        out.append((f"{t}-revoke_public", rf'REVOKE ALL ON TABLE {q} FROM PUBLIC'))
        out.append((f"{t}-revoke_app", rf'REVOKE ALL ON TABLE {q} FROM "vulnscope_app"'))
        if t != "alembic_version":
            out.append((f"{t}-grant", rf'GRANT [A-Z, ]+ ON TABLE {q} TO "vulnscope_app"'))
    return out


MUTANTS = _mutants()


def _seed(db: kit.ScratchDb, env: kit.StressEnv) -> None:
    kit.execute(
        db.admin_dsn,
        f'ALTER DEFAULT PRIVILEGES FOR ROLE "{env.admin_user}" IN SCHEMA public '
        'GRANT ALL ON TABLES TO PUBLIC, "vulnscope_app"',
    )


def _assert_clean_failure(db: kit.ScratchDb, proc: object) -> None:
    tables = [t for t in kit.user_tables(db) if t != "public.alembic_version"]
    assert not tables, f"user tables left after a failed migration: {tables}"
    if "public.alembic_version" in kit.user_tables(db):
        assert kit.fetchval(db.admin_dsn, "SELECT count(*) FROM public.alembic_version") == 0


@pytest.mark.parametrize(("name", "pattern"), MUTANTS, ids=[m[0] for m in MUTANTS])
def test_dropping_one_generated_statement_makes_the_migration_fail_closed(
    scratch_db_factory: Callable[..., kit.ScratchDb], stress_env: kit.StressEnv, name: str, pattern: str
) -> None:
    db = scratch_db_factory(migrate=False)
    _seed(db, stress_env)
    proc = kit.alembic_patched(stress_env, db, PATCH.format(pattern=pattern), "upgrade", "head")
    kit.record("helper_mutant", {"name": name, "rc": proc.returncode})
    assert "MUTANT matched" not in proc.stderr, f"mutant {name} did not match exactly one statement: {proc.stderr[-400:]}"
    assert proc.returncode != 0, f"MUTANT SURVIVED: dropping {name} still migrated successfully"
    assert "MigrationPreconditionError" in proc.stderr, (
        f"mutant {name} failed for the wrong reason (expected MigrationPreconditionError): "
        f"{proc.stderr[-500:]}"
    )
    _assert_clean_failure(db, proc)


def test_unmutated_control_with_seeded_defaults_succeeds_and_is_oracle_clean(
    scratch_db_factory: Callable[..., kit.ScratchDb], stress_env: kit.StressEnv
) -> None:
    db = scratch_db_factory(migrate=False)
    _seed(db, stress_env)
    proc = kit.alembic_patched(stress_env, db, "pass", "upgrade", "head")
    assert proc.returncode == 0, f"control failed: {proc.stderr[-500:]}"

    async def go(conn: Any) -> Any:
        return await oracle.violations(conn, "vulnscope_app")

    found = kit.with_conn(db.admin_dsn, go)
    assert not found, "control left violations: " + "; ".join(found[:4])


@pytest.mark.parametrize(("name", "pattern"), MUTANTS[:3], ids=[m[0] for m in MUTANTS[:3]])
def test_oracle_detects_seeded_drift_when_verification_is_bypassed(
    scratch_db_factory: Callable[..., kit.ScratchDb], stress_env: kit.StressEnv, name: str, pattern: str
) -> None:
    """Second line of defence: if verify_effective_privileges were bypassed, the independent
    oracle must still go red for the mutant (so the two controls do not share a blind spot)."""
    db = scratch_db_factory(migrate=False)
    _seed(db, stress_env)
    proc = kit.alembic_patched(
        stress_env, db, PATCH.format(pattern=pattern) + BYPASS_VERIFY, "upgrade", "head"
    )
    assert proc.returncode == 0, f"bypassed-verify mutant run failed to migrate: {proc.stderr[-500:]}"

    async def go(conn: Any) -> Any:
        return await oracle.violations(conn, "vulnscope_app")

    found = kit.with_conn(db.admin_dsn, go)
    assert found, f"ORACLE BLIND: dropping {name} left no oracle violation"
