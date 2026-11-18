# ruff: noqa: E501
"""Stress #7: two simultaneous ``alembic upgrade head`` on an empty scratch DB. R1.

Characterisation with a hard invariant: whatever the interleaving, the end state must be a
clean head: all 12 expected tables once, exactly one alembic_version row, zero oracle
violations, and at least one of the two processes succeeded. The outcome distribution
(return-code pairs, wall-clock) over N repetitions is appended to .reports/stress-records.jsonl.
If the distribution is not clean, the plan's fallback is a ``pg_advisory_xact_lock`` as the first
statement of ``upgrade()``; that decision is the owner's. A flaky repetition is a finding: this
test never retries.

N = VULNSCOPE_STRESS_CONCURRENT_REPS (default 5).
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
from collections.abc import Callable
from typing import Any

import pytest
import stress_db_oracle as oracle
import vulnscope_db_plugin as kit

pytestmark = pytest.mark.integration


def _spawn(env: kit.StressEnv, db: kit.ScratchDb) -> subprocess.Popen[str]:
    kit.assert_lab_url(db.admin_url, allow_shared=False)
    return subprocess.Popen(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=kit.REPO_ROOT,
        env=kit._alembic_env(env, db, None),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def test_two_simultaneous_upgrades_leave_a_clean_head(
    scratch_db_factory: Callable[..., kit.ScratchDb], stress_env: kit.StressEnv
) -> None:
    reps = int(os.environ.get("VULNSCOPE_STRESS_CONCURRENT_REPS", "5"))
    problems: list[str] = []
    for rep in range(reps):
        db = scratch_db_factory(migrate=False)
        t0 = time.monotonic()
        procs = [_spawn(stress_env, db), _spawn(stress_env, db)]
        outs = [p.communicate(timeout=180) for p in procs]
        wall = time.monotonic() - t0
        codes = sorted(p.returncode for p in procs)
        for o in outs:
            kit.assert_no_secret(stress_env, *o)
        kit.record("concurrent_upgrade", {"rep": rep, "codes": codes, "wall_s": round(wall, 2)})
        if codes[0] != 0:
            problems.append(f"rep {rep}: no process succeeded, codes={codes}")
            continue
        tables = sorted(kit.user_tables(db))
        want = sorted(f"public.{t}" for t in oracle.ALL_TABLES)
        if tables != want:
            problems.append(f"rep {rep}: tables {tables} != expected {want}")
        rows = kit.fetchval(db.admin_dsn, "SELECT count(*) FROM public.alembic_version")
        if rows != 1:
            problems.append(f"rep {rep}: alembic_version rows = {rows}")

        async def go(conn: Any) -> Any:
            return await oracle.violations(conn, "vulnscope_app")

        found = kit.with_conn(db.admin_dsn, go)
        if found:
            problems.append(f"rep {rep}: ACL invariants violated: " + "; ".join(found[:4]))
    assert not problems, "CONCURRENT UPGRADE not clean: " + " | ".join(problems)
