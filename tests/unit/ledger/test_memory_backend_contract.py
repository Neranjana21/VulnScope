# ruff: noqa: E501
"""InMemoryChainBackend: ChainBackend contract, normalisation, aliasing, paging, threads."""
from __future__ import annotations

import asyncio
import threading
from datetime import UTC, datetime, timedelta, timezone

import pytest

from vulnscope.ledger.canonical import genesis_hash
from vulnscope.ledger.errors import CanonicalizationError
from vulnscope.ledger.memory_backend import InMemoryChainBackend
from vulnscope.ledger.verify import verify

CID = "engagement:mem"
T0 = datetime(2026, 11, 19, 8, 30, tzinfo=UTC)


async def _fill(b: InMemoryChainBackend, n: int, cid: str = CID) -> None:
    for i in range(n):
        await b.append(cid, "policy.decision", "system", {"i": i}, T0 + timedelta(seconds=i))


async def test_seqs_prev_hashes_and_genesis() -> None:
    b = InMemoryChainBackend()
    await _fill(b, 4)
    rows = [e async for e in b.read(CID)]
    assert [e.seq for e in rows] == [0, 1, 2, 3]
    assert rows[0].prev_hash == genesis_hash(CID)
    assert all(rows[i].prev_hash == rows[i - 1].record_hash for i in range(1, 4))
    assert await b.record_count(CID) == 4
    head = await b.head(CID)
    assert head == rows[-1]


async def test_append_returns_exactly_what_read_returns_and_payload_is_normalised() -> None:
    b = InMemoryChainBackend()
    e = await b.append(CID, "evidence", "system", {"t": (1, 2), "n": {"x": [None, True]}}, T0)
    (r,) = [x async for x in b.read(CID)]
    assert e == r and e.payload == {"t": [1, 2], "n": {"x": [None, True]}}


async def test_no_aliasing_between_caller_storage_and_readers() -> None:
    b = InMemoryChainBackend()
    src: dict[str, object] = {"a": [1, 2]}
    e = await b.append(CID, "evidence", "system", src, T0)
    src["a"].append(3)  # type: ignore[attr-defined]
    e.payload["a"].append(4)  # type: ignore[attr-defined,index]
    (r1,) = [x async for x in b.read(CID)]
    r1.payload["a"].append(5)  # type: ignore[attr-defined,index]
    (r2,) = [x async for x in b.read(CID)]
    assert r2.payload == {"a": [1, 2]}
    assert (await verify(CID, b)).result == "ok"


async def test_read_paging_start_seq_and_limit() -> None:
    b = InMemoryChainBackend()
    await _fill(b, 2_500)  # crosses the 1024-entry chunk boundary twice
    assert [e.seq async for e in b.read(CID, 1_020, 10)] == list(range(1_020, 1_030))
    assert len([e async for e in b.read(CID, 2_000)]) == 500
    assert [e.seq async for e in b.read(CID, 0, 0)] == []
    assert [e.seq async for e in b.read(CID, 5_000)] == []
    assert len([e async for e in b.read(CID)]) == 2_500
    assert (await verify(CID, b)).records == 2_500


async def test_unknown_chain_is_empty_not_an_error() -> None:
    b = InMemoryChainBackend()
    other = "intake:nobody"
    assert await b.head(other) is None and await b.record_count(other) == 0
    assert [e async for e in b.read(other)] == []


@pytest.mark.parametrize("start,limit", [(-1, None), (0, -1)])
async def test_bad_read_arguments_raise(start: int, limit: int | None) -> None:
    with pytest.raises(CanonicalizationError):
        [e async for e in InMemoryChainBackend().read(CID, start, limit)]


async def test_timestamps_are_stored_as_utc_with_microseconds() -> None:
    b = InMemoryChainBackend()
    tz = timezone(timedelta(hours=-8))
    e = await b.append(CID, "evidence", "system", {}, datetime(2026, 1, 1, 0, 0, 0, 7, tzinfo=tz))
    assert e.ts == datetime(2026, 1, 1, 8, 0, 0, 7, tzinfo=UTC) and e.ts.utcoffset() == timedelta(0)


async def test_validation_happens_before_storage() -> None:
    b = InMemoryChainBackend()
    for args in (("bad", "evidence", "system", {}, T0), (CID, "Bad", "system", {}, T0),
                 (CID, "evidence", "", {}, T0), (CID, "evidence", "system", {}, datetime(2026, 1, 1))):
        with pytest.raises(CanonicalizationError):
            await b.append(*args)  # type: ignore[arg-type]
    assert await b.record_count(CID) == 0


async def test_payload_content_can_never_make_append_raise() -> None:
    b = InMemoryChainBackend()
    e = await b.append(CID, "policy.decision", "system", {"t": "\ud800", "f": 1.5, "b": b"x"}, T0)
    assert e.payload["sanitized"] is True and e.payload["f"] == "[float]"
    assert (await verify(CID, b)).result == "ok"


def test_threads_with_their_own_event_loops_keep_the_chain_linear() -> None:
    b = InMemoryChainBackend()
    errors: list[BaseException] = []

    def work() -> None:
        try:
            asyncio.run(_fill(b, 50))
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=work) for _ in range(16)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert not errors
    result = asyncio.run(verify(CID, b))
    assert (result.result, result.records) == ("ok", 800)


async def test_two_chains_are_independent() -> None:
    b = InMemoryChainBackend()
    await _fill(b, 3, "intake:org-a")
    await _fill(b, 5, "intake:org-b")
    assert await b.record_count("intake:org-a") == 3 and await b.record_count("intake:org-b") == 5
    a0 = (await b.head("intake:org-a"))
    assert a0 is not None and a0.chain_id == "intake:org-a"
