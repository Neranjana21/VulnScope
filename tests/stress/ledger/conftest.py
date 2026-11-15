"""Shared fixtures for ledger/ stress tests.

Provides:
- `crash_backend_factory`: a test-only ChainBackend wrapper that raises
  after N successful appends, used to simulate "the process died mid-
  append" without touching production code (R1).
- `test_database_url` / `pg_chain_backend`: Postgres-backed fixtures, SKIPPED
  (not failed) when no throwaway test database is configured via
  VULNSCOPE_TEST_DATABASE_URL. Heavy imports (vulnscope.db.session,
  vulnscope.ledger.postgres_backend) are deferred to inside the fixture body
  so that in-memory-only stress tests in this directory can still collect
  and run before Task B's Postgres backend exists.
"""
from __future__ import annotations

import os
from collections.abc import Iterator, Mapping
from datetime import datetime
from typing import Any

import pytest

TEST_DATABASE_URL_ENV = "VULNSCOPE_TEST_DATABASE_URL"


class CrashAfterNAppends:
    """Wraps a real ChainBackend and raises after N successful appends, to
    simulate a process crash mid-write. The wrapped backend's own atomicity
    (or lack of it) is exactly what is under test: after the injected
    crash, whatever the backend actually persisted must still be a
    verifiable, gapless prefix of the chain.
    """

    def __init__(self, inner: Any, crash_after: int) -> None:
        self._inner = inner
        self._crash_after = crash_after
        self._appends = 0

    def append(
        self, chain_id: str, kind: str, actor: str, payload: Mapping[str, object], ts: datetime
    ) -> Any:
        if self._appends >= self._crash_after:
            raise RuntimeError("simulated crash mid-append")
        entry = self._inner.append(chain_id, kind, actor, payload, ts)
        self._appends += 1
        return entry

    def read(self, chain_id: str, start_seq: int = 0, limit: int | None = None) -> Iterator[Any]:
        return self._inner.read(chain_id, start_seq, limit)

    def head(self, chain_id: str) -> Any:
        return self._inner.head(chain_id)

    def record_count(self, chain_id: str) -> int:
        return self._inner.record_count(chain_id)


@pytest.fixture
def crash_backend_factory():
    """Returns the CrashAfterNAppends class; call
    crash_backend_factory(inner_backend, crash_after=N)."""
    return CrashAfterNAppends


@pytest.fixture
def test_database_url() -> str:
    url = os.environ.get(TEST_DATABASE_URL_ENV)
    if not url:
        pytest.skip(
            f"{TEST_DATABASE_URL_ENV} not set; Postgres-backed ledger stress "
            "tests need a throwaway CI/dev Postgres instance (see "
            "docs/gates/slice0-pre-stress.md)"
        )
    return url


@pytest.fixture
def pg_chain_backend(test_database_url: str):
    """Construction of PostgresChainBackend.

    Recheck update (docs/gates/slice0-pre-stress-recheck.md): the signature
    ambiguity originally flagged here (docs/gates/slice0-pre-stress.md) is
    resolved. docs/gates/slice0-plan.md Section 3.7 (fixes STR-1) now PINS
    `db/session.get_engine(database_url: str) -> Engine` and
    `PostgresChainBackend(engine: Engine)`, matching this fixture's calls
    exactly. The `try/except ImportError -> skip` below is kept as a
    defensive fallback for the pre-implementation state (Task 0/B have not
    landed yet), not because the signature is still in doubt -- once Task 0
    lands, a missing `get_engine` would indicate a real regression against
    the pinned plan, not an open question.
    """
    try:
        from vulnscope.db.session import get_engine
    except ImportError:
        pytest.skip(
            "vulnscope.db.session.get_engine not found; per "
            "docs/gates/slice0-plan.md Section 3.7 this is pinned and "
            "should exist once Task 0 lands -- if it's missing after that, "
            "it's a regression against the plan, not an open ambiguity"
        )
    from vulnscope.ledger.postgres_backend import PostgresChainBackend

    engine = get_engine(test_database_url)
    return PostgresChainBackend(engine)
