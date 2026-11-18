# ruff: noqa: E501
"""Stress #13 (reduced per GR-STR-21 to the stress tree's own lock). R1.

Two OS processes contend for the same advisory lock on the shared dev DB. The mechanics are
tested with a dedicated test key (never the real SHARED_LOCK_KEY, so this test cannot collide with
a session that legitimately holds the shared-DB lock in oracle shared mode): while one process
holds it, the second fails CLEARLY ("shared database is in use") within its bound, no
hang; after release the second succeeds. No data is read or written.
"""
from __future__ import annotations

import os
import subprocess
import sys
import time

import pytest
import vulnscope_db_plugin as kit

pytestmark = pytest.mark.integration

TEST_KEY = 0x56554C4E53540001
BOUND_S = 2.0

CHILD = """
import sys, time
import vulnscope_db_plugin as k
t0 = time.monotonic()
try:
    k.AdvisoryLock(k.to_dsn(__import__('os').environ[k.ADMIN_ENV]), {key}, {bound}).acquire()
except k.LockUnavailable as e:
    print("BUSY after %.2fs: %s" % (time.monotonic() - t0, e))
    sys.exit(7)
print("ACQUIRED after %.2fs" % (time.monotonic() - t0))
"""


def _child(env: kit.StressEnv) -> tuple[int, str, float]:
    e = {**os.environ, "PYTHONPATH": f"{kit.HERE}:{kit.REPO_ROOT / 'src'}"}
    t0 = time.monotonic()
    p = subprocess.run(
        [sys.executable, "-c", CHILD.format(key=TEST_KEY, bound=BOUND_S)],
        env=e, capture_output=True, text=True, timeout=60,
    )
    kit.assert_no_secret(env, p.stdout, p.stderr)
    return p.returncode, p.stdout + p.stderr, time.monotonic() - t0


def test_second_process_fails_clearly_within_the_bound_then_succeeds_after_release(
    stress_env: kit.StressEnv,
) -> None:
    holder = kit.AdvisoryLock(kit.to_dsn(stress_env.admin_url), TEST_KEY, 5)
    holder.acquire()
    try:
        rc, out, elapsed = _child(stress_env)
        assert rc == 7, f"SERIAL LOCK: second process was not refused (rc={rc}): {out}"
        assert "shared database is in use" in out, f"SERIAL LOCK: unclear refusal message: {out}"
        assert elapsed < BOUND_S + 15, f"SERIAL LOCK: refusal took {elapsed:.1f}s, bound {BOUND_S}s"
        kit.record("serial_lock", {"refusal_wall_s": round(elapsed, 2), "bound_s": BOUND_S})
    finally:
        holder.release()
    rc, out, _ = _child(stress_env)
    assert rc == 0 and "ACQUIRED" in out, f"SERIAL LOCK: lock not released for the next process: {out}"


def test_real_shared_lock_key_is_distinct_from_the_session_key() -> None:
    assert kit.SHARED_LOCK_KEY != kit.SESSION_LOCK_KEY != TEST_KEY
    assert kit.SHARED_LOCK_KEY != TEST_KEY
