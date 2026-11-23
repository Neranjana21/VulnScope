"""Shared fixtures for ledger/ stress tests.

Provides:
- `crash_backend_factory`: a test-only async ChainBackend wrapper that
  raises after N successful appends, used to simulate "the process died
  mid-append" without touching production code (R1).
- `test_database_url` / `pg_chain_backend`: Postgres-backed fixtures, SKIPPED
  (not failed) when no throwaway test database is configured via
  VULNSCOPE_TEST_DATABASE_URL. Heavy imports (vulnscope.db.session,
  vulnscope.ledger.postgres_backend) are deferred to inside the fixture body
  so that in-memory-only stress tests in this directory can still collect
  and run before Task B's Postgres backend exists.

Async update (docs/gates/slice0-pre-stress-recheck.md round 3): now that
`asyncpg` is approved and `ChainBackend` (docs/gates/slice0-plan.md §3.2,
pinned §3.7/§3.8) is an async Protocol (`async def append/read/head/
record_count`, with `read()` an async generator per its
`AsyncIterator[LedgerEntry]` return type), `CrashAfterNAppends`'s methods
are `async def` too, since it wraps/proxies a `ChainBackend`.
`pg_chain_backend` now builds an `AsyncEngine` via
`db.session.get_async_engine(database_url) -> AsyncEngine` (a plain,
non-async factory function -- constructing an async engine does not
itself need an event loop; only using it to run a query does) and
constructs `PostgresChainBackend(engine: AsyncEngine)` from it, per §3.7's
corrected pin. This is a signature-mechanics update only; no assertion or
invariant in the test files that use these fixtures changed as a result
(see the round-3 addendum in docs/gates/slice0-pre-stress-recheck.md for
exactly what *did* need a mechanical await/async-def change downstream in
the test files themselves, which is expected and unavoidable once the
Protocol they call is async).
"""
from __future__ import annotations

from collections.abc import AsyncIterator, Mapping
from datetime import datetime
from typing import Any

import pytest
from stress_dbguard import require_task_database_url, skip_or_fail

TEST_DATABASE_URL_ENV = "VULNSCOPE_TEST_DATABASE_URL"


class CrashAfterNAppends:
    """Wraps a real (async) ChainBackend and raises after N successful
    appends, to simulate a process crash mid-write. The wrapped backend's
    own atomicity (or lack of it) is exactly what is under test: after the
    injected crash, whatever the backend actually persisted must still be
    a verifiable, gapless prefix of the chain.
    """

    def __init__(self, inner: Any, crash_after: int) -> None:
        self._inner = inner
        self._crash_after = crash_after
        self._appends = 0

    async def append(
        self, chain_id: str, kind: str, actor: str, payload: Mapping[str, object], ts: datetime
    ) -> Any:
        if self._appends >= self._crash_after:
            raise RuntimeError("simulated crash mid-append")
        entry = await self._inner.append(chain_id, kind, actor, payload, ts)
        self._appends += 1
        return entry

    async def read(
        self, chain_id: str, start_seq: int = 0, limit: int | None = None
    ) -> AsyncIterator[Any]:
        async for entry in self._inner.read(chain_id, start_seq, limit):
            yield entry

    async def head(self, chain_id: str) -> Any:
        return await self._inner.head(chain_id)

    async def record_count(self, chain_id: str) -> int:
        return await self._inner.record_count(chain_id)


@pytest.fixture
def crash_backend_factory():
    """Returns the CrashAfterNAppends class; call
    crash_backend_factory(inner_backend, crash_after=N). The returned
    instance's methods are all `async def`/`await`-able now, matching the
    async `ChainBackend` Protocol it wraps -- callers must `await
    crashy.append(...)` etc. and use `async for entry in crashy.read(...)`.
    """
    return CrashAfterNAppends


@pytest.fixture
def test_database_url() -> str:
    # 2026-11-19 owner decision: refuse any database that is not a disposable
    # vulnscope_task<letters>_<8 hex> on 127.0.0.1:5432 (a failure, not a skip), and turn the
    # unset-env skip into a failure under VULNSCOPE_REQUIRE_INTEGRATION=1. Fixed-text messages.
    return require_task_database_url()


@pytest.fixture
def pg_chain_backend(test_database_url: str):
    """Construction of PostgresChainBackend against an AsyncEngine.

    Async update (docs/gates/slice0-pre-stress-recheck.md round 3):
    docs/gates/slice0-plan.md Section 3.7/3.8 corrects the earlier (round-1)
    pin from a sync `get_engine(...) -> Engine` to
    `get_async_engine(database_url: str) -> AsyncEngine`, and
    `PostgresChainBackend.__init__(self, engine: AsyncEngine) -> None`.
    `get_async_engine` itself is a plain (non-async) factory function --
    building an `AsyncEngine` object does not require an event loop, only
    actually running a query against it does -- so this fixture stays a
    regular, non-async `pytest.fixture`; only the callers that later
    `await` the backend's methods need to be async.

    The `try/except ImportError -> skip` below is kept as a defensive
    fallback for the pre-implementation state (Task 0/B have not landed
    yet), not because the signature is still in doubt -- once Task 0
    lands, a missing `get_async_engine` would indicate a real regression
    against the pinned plan, not an open question.
    """
    try:
        from vulnscope.db.session import get_async_engine
    except ImportError:
        skip_or_fail(
            "vulnscope.db.session.get_async_engine not found; per "
            "docs/gates/slice0-plan.md Section 3.7/3.8 this is pinned and "
            "should exist once Task 0 lands -- if it's missing after that, "
            "it's a regression against the plan, not an open ambiguity"
        )
    from vulnscope.ledger.postgres_backend import PostgresChainBackend

    engine = get_async_engine(test_database_url)
    return PostgresChainBackend(engine)
