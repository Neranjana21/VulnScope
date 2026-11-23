# ruff: noqa: E501
"""The same ChainBackend contract cases against BOTH backends (memory and postgres)."""
from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from ledger_pg_support import open_backend

from vulnscope.ledger.chain import ChainBackend
from vulnscope.ledger.memory_backend import InMemoryChainBackend
from vulnscope.ledger.verify import verify

pytestmark = pytest.mark.integration
T0 = datetime(2026, 11, 19, 8, 30, tzinfo=UTC)


@pytest.fixture(params=["memory", "postgres"])
async def any_backend(request: pytest.FixtureRequest) -> AsyncIterator[ChainBackend]:
    if request.param == "memory":
        yield InMemoryChainBackend()
        return
    db = request.getfixturevalue("ledger_db")
    engine, b = await open_backend(db)
    try:
        yield b
    finally:
        await engine.dispose()


async def _fill(b: ChainBackend, cid: str, n: int) -> None:
    for i in range(n):
        await b.append(cid, "policy.decision", "system", {"i": i}, T0 + timedelta(seconds=i))


async def test_append_returns_what_read_and_head_return(any_backend: ChainBackend) -> None:
    cid = f"engagement:{uuid.uuid4()}"
    e = await any_backend.append(cid, "evidence", "user:alice", {"t": (1, 2), "n": {"k": None}}, T0)
    (r,) = [x async for x in any_backend.read(cid)]
    assert e == r == await any_backend.head(cid)
    assert e.payload == {"t": [1, 2], "n": {"k": None}} and e.ts == T0 and e.seq == 0


async def test_unknown_chain_is_empty(any_backend: ChainBackend) -> None:
    cid = f"engagement:{uuid.uuid4()}"
    assert await any_backend.head(cid) is None and await any_backend.record_count(cid) == 0
    assert [x async for x in any_backend.read(cid)] == []


@pytest.mark.parametrize("n", [499, 500, 501])
async def test_batch_boundaries(any_backend: ChainBackend, n: int) -> None:
    cid = f"engagement:{uuid.uuid4()}"
    await _fill(any_backend, cid, n)
    rows = [x async for x in any_backend.read(cid)]
    assert [x.seq for x in rows] == list(range(n))
    assert await any_backend.record_count(cid) == n
    assert (await verify(cid, any_backend)).records == n


async def test_start_seq_and_limit(any_backend: ChainBackend) -> None:
    cid = f"engagement:{uuid.uuid4()}"
    await _fill(any_backend, cid, 30)
    assert [x.seq async for x in any_backend.read(cid, 5, 7)] == list(range(5, 12))
    assert [x.seq async for x in any_backend.read(cid, 28)] == [28, 29]
    assert [x.seq async for x in any_backend.read(cid, 0, 0)] == []
    assert [x.seq async for x in any_backend.read(cid, 99)] == []


async def test_non_utc_timestamps_round_trip_as_utc_microseconds(any_backend: ChainBackend) -> None:
    from datetime import timezone

    cid = f"engagement:{uuid.uuid4()}"
    ts = datetime(2026, 1, 1, 0, 0, 0, 123456, tzinfo=timezone(timedelta(hours=-8)))
    e = await any_backend.append(cid, "evidence", "system", {}, ts)
    (r,) = [x async for x in any_backend.read(cid)]
    assert e.ts == r.ts == ts and r.ts.utcoffset() == timedelta(0) and r.ts.microsecond == 123456
    assert (await verify(cid, any_backend)).result == "ok"


async def test_hostile_identifiers_are_refused_before_storage(any_backend: ChainBackend) -> None:
    from vulnscope.ledger.errors import CanonicalizationError

    for args in (("engagement:x\n", "evidence", "system"), (f"engagement:{uuid.uuid4()}", "Evidence", "system"),
                 (f"engagement:{uuid.uuid4()}", "evidence", "a b")):
        with pytest.raises(CanonicalizationError):
            await any_backend.append(*args, {}, T0)  # type: ignore[arg-type]
    with pytest.raises(CanonicalizationError):
        await any_backend.append(f"engagement:{uuid.uuid4()}", "evidence", "system", {}, datetime(2026, 1, 1))


async def test_two_orgs_intake_chains_are_isolated(any_backend: ChainBackend) -> Any:
    a, b = f"intake:{uuid.uuid4()}", f"intake:{uuid.uuid4()}"
    await _fill(any_backend, a, 3)
    await _fill(any_backend, b, 5)
    assert await any_backend.record_count(a) == 3 and await any_backend.record_count(b) == 5
    assert all(e.chain_id == a for e in [x async for x in any_backend.read(a)])
