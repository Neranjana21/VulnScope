"""Stress: simulate a process crash mid-append; chain remains verifiable up
to the last committed record.

Catalogue row: docs/stress-tests.md "Ledger" -> "Crash safety: kill the
process mid-append; chain remains verifiable."

A literal process kill is out of reach for a unit/stress test running in
the same process; this uses a fault-injected backend wrapper (test-only
code: tests/stress/ledger/conftest.py's CrashAfterNAppends) that raises
partway through a sequence of append() calls, modelling "the process died
after some appends committed and before the next one did." What is actually
under test is the PRODUCTION backend's own atomicity: whatever got
persisted before the simulated crash must remain a clean, verifiable,
gapless prefix -- no half-written record, no dangling seq -- and a
"restarted" process must be able to resume appending with no gap.

Async update (docs/gates/slice0-pre-stress-recheck.md round 3): `ChainBackend`
(docs/gates/slice0-plan.md §3.2/§3.7/§3.8) is now an async Protocol, so
`CrashAfterNAppends` (tests/stress/ledger/conftest.py) and `verify()` are
awaited throughout below. This is a mechanical change only -- the sequence
of events (append some, crash, verify the prefix, resume, verify again) and
every assertion are unchanged from the pre-async version.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from vulnscope.ledger.memory_backend import InMemoryChainBackend
from vulnscope.ledger.verify import verify


@pytest.mark.asyncio
async def test_chain_verifiable_after_simulated_crash_mid_sequence(crash_backend_factory) -> None:
    inner = InMemoryChainBackend()
    chain_id = "engagement:stress-crash"
    crashy = crash_backend_factory(inner, crash_after=7)

    committed = 0
    now = datetime.now(timezone.utc)
    with pytest.raises(RuntimeError, match="simulated crash"):
        for i in range(20):
            await crashy.append(chain_id, "policy.decision", "system", {"i": i}, now)
            committed += 1

    assert committed == 7

    # Verify against the UNDERLYING backend (what a real process restart
    # would see on disk/in the DB) -- not the crashy wrapper, which has no
    # persisted state of its own.
    result = await verify(chain_id, inner)
    assert result.result == "ok"
    assert result.records == 7

    # A fresh process picking the chain back up must be able to continue
    # appending from the last committed seq with no gap.
    resumed_entry = await inner.append(chain_id, "policy.decision", "system", {"i": "resume"}, now)
    assert resumed_entry.seq == 7

    final = await verify(chain_id, inner)
    assert final.result == "ok"
    assert final.records == 8


@pytest.mark.asyncio
@pytest.mark.requires_postgres
async def test_postgres_chain_verifiable_after_simulated_crash(pg_chain_backend, crash_backend_factory) -> None:
    """Same scenario against the real transactional backend: a crash that
    interrupts one in-flight append() must not leave a partially committed
    row (the DB transaction either fully commits or not at all), so the
    gapless-prefix property must hold against Postgres too, not only
    against the in-memory fake."""
    chain_id = "engagement:stress-crash-pg"
    crashy = crash_backend_factory(pg_chain_backend, crash_after=5)
    now = datetime.now(timezone.utc)

    committed = 0
    with pytest.raises(RuntimeError, match="simulated crash"):
        for i in range(10):
            await crashy.append(chain_id, "policy.decision", "system", {"i": i}, now)
            committed += 1

    assert committed == 5
    result = await verify(chain_id, pg_chain_backend)
    assert result.result == "ok"
    assert result.records == 5
