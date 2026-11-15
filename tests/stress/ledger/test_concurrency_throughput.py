"""Stress: many concurrent writers append to one ledger chain; seq stays
gapless/linear; throughput measured against R6 (>=200 records/s per
engagement).

Catalogue row: docs/stress-tests.md "Ledger" -> "Concurrency: many writers
appending; chain stays linear; no gaps." + the throughput half of R6.
Supports: Slice 0 AC9 ("Concurrent appends to one chain stay linear with no
gaps (PostgreSQL integration test)").

This is the STRESS variant of Task B's integration test
(tests/integration/ledger/test_postgres_concurrency.py, owned by the
implementer per docs/gates/slice0-plan.md Task B): higher thread count and
an explicit throughput measurement, run against both InMemoryChainBackend
(deterministic, always runs in CI) and PostgresChainBackend (skipped if
VULNSCOPE_TEST_DATABASE_URL is unset).

Recheck note (docs/gates/slice0-pre-stress-recheck.md, re SEC-5): Task 0's
migration now adds `UNIQUE(chain_id, seq)` on `ledger_entries`. Under this
file's NORMAL (non-adversarial) concurrent workload -- every writer only
ever calls the real backend's own `append()`, which is required to take
the chain-head row lock before computing `seq` -- the constraint should
never actually fire; the row lock is what is supposed to prevent two
writers from ever computing the same `seq` in the first place. This is
different from Task B's own adversarial sub-test
(`test_postgres_concurrency.py`), which deliberately bypasses the lock to
prove the constraint catches a lock bug. Here, the constraint is a backstop
we do NOT expect to trip; `_hammer` below propagates any exception
(including a SQLAlchemy `IntegrityError`) through `future.result()` without
swallowing it, and `_assert_gapless_and_linear`'s "no duplicate seq" check
would also independently catch a constraint-bypassing lock bug if one
somehow still let a duplicate seq become readable. `test_scale_append_verify.py`
is single-threaded (no concurrent writers), so the UNIQUE constraint is not
exercised there at all; `test_crash_safety_simulation.py` only ever stops
calling append() early, it never produces two inserts for the same seq, so
the constraint is not exercised there either.
"""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import pytest

from vulnscope.ledger.memory_backend import InMemoryChainBackend
from vulnscope.ledger.verify import verify

WRITER_THREADS = 32
APPENDS_PER_THREAD = 60
TOTAL_APPENDS = WRITER_THREADS * APPENDS_PER_THREAD
R6_LEDGER_APPEND_FLOOR_RPS = 200.0  # docs/decisions.md R6


def _hammer(backend, chain_id: str) -> None:
    # Any exception here -- including a SQLAlchemy IntegrityError from the
    # Task 0 UNIQUE(chain_id, seq) constraint (SEC-5) -- propagates through
    # the calling future's .result() uncaught; see the recheck note above:
    # under this normal, lock-respecting workload, that constraint must
    # never actually fire.
    for i in range(APPENDS_PER_THREAD):
        backend.append(
            chain_id,
            "policy.decision",
            "system",
            {"i": i},
            datetime.now(timezone.utc),
        )


def _assert_no_integrity_errors(futures) -> None:
    errors: list[BaseException] = []
    for f in futures:
        try:
            f.result()
        except BaseException as exc:  # noqa: BLE001 - captured for the report
            errors.append(exc)
    assert not errors, (
        f"{len(errors)} writer thread(s) raised under normal concurrent "
        f"load (first: {errors[0]!r}); if any of these is an IntegrityError "
        "from the UNIQUE(chain_id, seq) constraint (SEC-5), the chain-head "
        "row lock is not actually serializing writers -- that is a P1-worthy "
        "finding, not something to retry past"
    )


def _assert_gapless_and_linear(backend, chain_id: str) -> None:
    entries = list(backend.read(chain_id))
    seqs = sorted(e.seq for e in entries)
    assert seqs == list(range(len(seqs))), (
        f"gaps or duplicate seqs detected: first 10 of {len(seqs)} -> {seqs[:10]}"
    )
    assert len(entries) == TOTAL_APPENDS

    result = verify(chain_id, backend)
    assert result.result == "ok", f"verify() returned {result.result!r}, expected 'ok'"


def test_memory_backend_concurrent_writers_no_gaps_and_throughput() -> None:
    backend = InMemoryChainBackend()
    chain_id = "engagement:stress-concurrency-memory"

    start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=WRITER_THREADS) as pool:
        futures = [pool.submit(_hammer, backend, chain_id) for _ in range(WRITER_THREADS)]
        _assert_no_integrity_errors(futures)
    elapsed = time.perf_counter() - start

    _assert_gapless_and_linear(backend, chain_id)

    throughput = TOTAL_APPENDS / elapsed
    print(
        f"InMemoryChainBackend: {TOTAL_APPENDS} appends across {WRITER_THREADS} "
        f"threads in {elapsed:.3f}s = {throughput:.1f} records/s"
    )
    assert throughput >= R6_LEDGER_APPEND_FLOOR_RPS, (
        f"in-memory backend throughput {throughput:.1f} records/s is below the "
        f"R6 floor of {R6_LEDGER_APPEND_FLOOR_RPS} records/s per engagement -- "
        "in-memory has no I/O, so falling below this floor signals a lock/"
        "contention bug in the chain-head serialization, not an infra limit"
    )


@pytest.mark.requires_postgres
def test_postgres_backend_concurrent_writers_no_gaps(pg_chain_backend) -> None:
    chain_id = "engagement:stress-concurrency-pg"

    start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=WRITER_THREADS) as pool:
        futures = [pool.submit(_hammer, pg_chain_backend, chain_id) for _ in range(WRITER_THREADS)]
        _assert_no_integrity_errors(futures)
    elapsed = time.perf_counter() - start

    _assert_gapless_and_linear(pg_chain_backend, chain_id)

    throughput = TOTAL_APPENDS / elapsed
    print(
        f"PostgresChainBackend: {TOTAL_APPENDS} appends across {WRITER_THREADS} "
        f"threads in {elapsed:.3f}s = {throughput:.1f} records/s"
    )
    # Real I/O + row-lock serialization is slower than in-memory and more
    # sensitive to CI hardware; the real number must be recorded in the
    # post-gate against the R6 target of 200 records/s regardless of
    # pass/fail. A conservative floor here only catches a gross regression
    # (e.g. a missing index or lock misuse), not R6 compliance itself.
    conservative_floor = R6_LEDGER_APPEND_FLOOR_RPS / 10
    assert throughput >= conservative_floor, (
        f"Postgres backend throughput {throughput:.1f} records/s is far below "
        f"even the conservative floor of {conservative_floor} records/s; "
        f"R6's actual target is {R6_LEDGER_APPEND_FLOOR_RPS} records/s -- "
        "record the real measured number in the post-gate either way"
    )
