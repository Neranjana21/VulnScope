"""Stress: many concurrent writers append to one ledger chain; seq stays
gapless/linear; throughput measured against R6 (>=200 records/s per
engagement).

Catalogue row: docs/stress-tests.md "Ledger" -> "Concurrency: many writers
appending; chain stays linear; no gaps." + the throughput half of R6.
Supports: Slice 0 AC9 ("Concurrent appends to one chain stay linear with no
gaps (PostgreSQL integration test)").

This is the STRESS variant of Task B's integration test
(tests/integration/ledger/test_postgres_concurrency.py, owned by the
implementer per docs/gates/slice0-plan.md Task B): higher writer count and
an explicit throughput measurement, run against both InMemoryChainBackend
(deterministic, always runs in CI) and PostgresChainBackend (skipped if
VULNSCOPE_TEST_DATABASE_URL is unset).

Recheck note (docs/gates/slice0-pre-stress-recheck.md, re SEC-5): Task 0's
migration adds `UNIQUE(chain_id, seq)` on `ledger_entries`. Under this
file's NORMAL (non-adversarial) concurrent workload -- every writer only
ever calls the real backend's own `append()`, which is required to take
the chain-head row lock before computing `seq` -- the constraint should
never actually fire; the row lock is what is supposed to prevent two
writers from ever computing the same `seq` in the first place. This is
different from Task B's own adversarial sub-test
(`test_postgres_concurrency.py`), which deliberately bypasses the lock to
prove the constraint catches a lock bug. Here, the constraint is a backstop
we do NOT expect to trip. `test_scale_append_verify.py` is single-threaded
(no concurrent writers), so the UNIQUE constraint is not exercised there at
all; `test_crash_safety_simulation.py` only ever stops calling append()
early, it never produces two inserts for the same seq, so the constraint
is not exercised there either.

Async update (docs/gates/slice0-pre-stress-recheck.md round 3): `ChainBackend`
(docs/gates/slice0-plan.md §3.2/§3.7/§3.8) is now an async Protocol
(`async def append/read/head/record_count`) because `PostgresChainBackend`
is `asyncpg`-backed; `InMemoryChainBackend` implements the same async
signatures with trivial, non-I/O-bound bodies. This changes the
CONCURRENCY MECHANICS of the two tests below, deliberately differently,
to keep the actual stress property each test is checking intact rather
than accidentally defeating it:

- The in-memory test keeps real OS threads (`ThreadPoolExecutor`) -- each
  worker thread runs its own short-lived event loop via `asyncio.run(...)`
  to drive its sequence of `await backend.append(...)` calls. OS threads
  still interleave via the GIL at the bytecode level even though
  `InMemoryChainBackend`'s trivial `async def` body never itself
  `await`s anything internally, so this preserves the original "real
  concurrent races across OS threads" stress property. Using
  `asyncio.gather()` tasks on a single thread/loop instead would NOT: with
  no real internal `await` point, cooperative tasks would simply run to
  completion back-to-back without ever actually interleaving, defeating
  the point of a concurrency stress test.
- The Postgres test switches entirely to `asyncio.gather()` over many
  concurrent async tasks sharing ONE `AsyncEngine`/event loop, matching
  docs/gates/slice0-plan.md Task B's own SEC-7 `asyncio.gather()` variant
  rationale: `asyncpg` connections/pools are bound to the event loop that
  first used them, so spreading a single shared `AsyncEngine` across
  multiple OS threads (each running its own `asyncio.run()`/event loop, as
  the in-memory test does) is the actual anti-pattern `asyncpg` warns
  against, not a stress-test nicety. `asyncio.gather()` on one loop is the
  architecturally correct way to drive many concurrent writers against one
  async engine, and real I/O `await` points inside `PostgresChainBackend`
  (unlike the in-memory fake) still give genuine interleaving opportunities
  for a lock bug to show up.
"""
from __future__ import annotations

import asyncio
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import pytest

from vulnscope.ledger.memory_backend import InMemoryChainBackend
from vulnscope.ledger.verify import verify

WRITER_THREADS = 32  # in-memory test: real OS threads
APPENDS_PER_THREAD = 60
TOTAL_APPENDS = WRITER_THREADS * APPENDS_PER_THREAD

WRITER_TASKS = 32  # postgres test: asyncio.gather() tasks on one loop
APPENDS_PER_TASK = 60
TOTAL_TASK_APPENDS = WRITER_TASKS * APPENDS_PER_TASK

R6_LEDGER_APPEND_FLOOR_RPS = 200.0  # docs/decisions.md R6


async def _hammer_async(backend, chain_id: str, count: int) -> None:
    # Any exception here -- including a SQLAlchemy IntegrityError from the
    # Task 0 UNIQUE(chain_id, seq) constraint (SEC-5) -- propagates
    # uncaught; see the module docstring: under this normal, lock-
    # respecting workload, that constraint must never actually fire.
    for i in range(count):
        await backend.append(
            chain_id,
            "policy.decision",
            "system",
            {"i": i},
            datetime.now(timezone.utc),
        )


def _hammer_thread(backend, chain_id: str) -> None:
    # Each OS thread drives its own short-lived event loop; this is safe
    # for InMemoryChainBackend (no real connection/loop affinity to break)
    # and is what preserves genuine OS-thread-level race exposure -- see
    # the module docstring for why this differs from the Postgres variant.
    asyncio.run(_hammer_async(backend, chain_id, APPENDS_PER_THREAD))


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


def _assert_no_integrity_errors_async(results: list[object]) -> None:
    errors = [r for r in results if isinstance(r, BaseException)]
    assert not errors, (
        f"{len(errors)} writer task(s) raised under normal concurrent "
        f"load (first: {errors[0]!r}); if any of these is an IntegrityError "
        "from the UNIQUE(chain_id, seq) constraint (SEC-5), the chain-head "
        "row lock is not actually serializing writers -- that is a P1-worthy "
        "finding, not something to retry past"
    )


async def _assert_gapless_and_linear(backend, chain_id: str, expected_total: int) -> None:
    entries = [entry async for entry in backend.read(chain_id)]
    seqs = sorted(e.seq for e in entries)
    assert seqs == list(range(len(seqs))), (
        f"gaps or duplicate seqs detected: first 10 of {len(seqs)} -> {seqs[:10]}"
    )
    assert len(entries) == expected_total

    result = await verify(chain_id, backend)
    assert result.result == "ok", f"verify() returned {result.result!r}, expected 'ok'"


@pytest.mark.asyncio
async def test_memory_backend_concurrent_writers_no_gaps_and_throughput() -> None:
    backend = InMemoryChainBackend()
    chain_id = "engagement:stress-concurrency-memory"

    start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=WRITER_THREADS) as pool:
        futures = [pool.submit(_hammer_thread, backend, chain_id) for _ in range(WRITER_THREADS)]
        _assert_no_integrity_errors(futures)
    elapsed = time.perf_counter() - start

    await _assert_gapless_and_linear(backend, chain_id, TOTAL_APPENDS)

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


@pytest.mark.asyncio
@pytest.mark.requires_postgres
async def test_postgres_backend_concurrent_writers_no_gaps(pg_chain_backend) -> None:
    chain_id = "engagement:stress-concurrency-pg"

    start = time.perf_counter()
    results = await asyncio.gather(
        *(
            _hammer_async(pg_chain_backend, chain_id, APPENDS_PER_TASK)
            for _ in range(WRITER_TASKS)
        ),
        return_exceptions=True,
    )
    elapsed = time.perf_counter() - start
    _assert_no_integrity_errors_async(results)

    await _assert_gapless_and_linear(pg_chain_backend, chain_id, TOTAL_TASK_APPENDS)

    throughput = TOTAL_TASK_APPENDS / elapsed
    print(
        f"PostgresChainBackend: {TOTAL_TASK_APPENDS} appends across {WRITER_TASKS} "
        f"asyncio tasks in {elapsed:.3f}s = {throughput:.1f} records/s"
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
