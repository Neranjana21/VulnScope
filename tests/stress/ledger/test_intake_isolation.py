# ruff: noqa: E501
"""Stress (R1): per-org intake-chain isolation. docs/stress-tests.md Ledger "intake-chain isolation
per org"; threat T9; design task-b-design.md F13 and R1-4 (hostile engagement ids route to the org
intake chain, so chain-id grammar and chain separation must hold). B is org-blind: ownership checks
are Task D's. Here: distinct genesis, independent seq, no cross-read, no interleave under
concurrency, foreign-chain entries rejected by verify, hostile chain ids refused before storage.
"""
from __future__ import annotations

import asyncio
import threading
import uuid
from dataclasses import replace
from datetime import timedelta

import pytest
from ledger_r1_support import BASE_TS, ListBackend, mods, ref_genesis, run

ORG_A = "intake:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
ORG_B = "intake:bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"


async def _append(b, cid, n, tag):
    out = []
    for i in range(n):
        out.append(await b.append(cid, "policy.decision", "system", {"org": tag, "i": i}, BASE_TS + timedelta(seconds=i)))
    return out


async def test_distinct_genesis_and_independent_sequences() -> None:
    m = mods()
    b = m.memory_backend.InMemoryChainBackend()
    a = await _append(b, ORG_A, 3, "A")
    c = await _append(b, ORG_B, 5, "B")
    assert [e.seq for e in a] == [0, 1, 2] and [e.seq for e in c] == [0, 1, 2, 3, 4]
    assert a[0].prev_hash == ref_genesis(ORG_A) and c[0].prev_hash == ref_genesis(ORG_B)
    assert a[0].prev_hash != c[0].prev_hash
    assert {e.record_hash for e in a}.isdisjoint({e.record_hash for e in c})
    assert (await m.verify.verify(ORG_A, b)).records == 3 and (await m.verify.verify(ORG_B, b)).records == 5


async def test_no_cross_read_head_or_count() -> None:
    m = mods()
    b = m.memory_backend.InMemoryChainBackend()
    await _append(b, ORG_A, 4, "A")
    await _append(b, ORG_B, 2, "B")
    for cid, tag, n in ((ORG_A, "A", 4), (ORG_B, "B", 2)):
        rows = [e async for e in b.read(cid)]
        assert len(rows) == n == await b.record_count(cid)
        assert all(e.chain_id == cid and e.payload["org"] == tag for e in rows)
        assert (await b.head(cid)).payload["org"] == tag
    assert await b.head("intake:cccccccc-cccc-4ccc-8ccc-cccccccccccc") is None
    assert await b.record_count("intake:cccccccc-cccc-4ccc-8ccc-cccccccccccc") == 0
    assert [e async for e in b.read("intake:cccccccc-cccc-4ccc-8ccc-cccccccccccc")] == []


async def test_engagement_and_intake_chains_with_same_suffix_do_not_collide() -> None:
    m = mods()
    b = m.memory_backend.InMemoryChainBackend()
    suffix = str(uuid.uuid4())
    e1 = (await _append(b, f"engagement:{suffix}", 2, "E"))[0]
    i1 = (await _append(b, f"intake:{suffix}", 2, "I"))[0]
    assert e1.prev_hash != i1.prev_hash and e1.record_hash != i1.record_hash
    assert await b.record_count(f"engagement:{suffix}") == 2 == await b.record_count(f"intake:{suffix}")


async def test_entry_moved_between_orgs_is_caught_by_verify() -> None:
    m = mods()
    b = m.memory_backend.InMemoryChainBackend()
    await _append(b, ORG_A, 6, "A")
    await _append(b, ORG_B, 6, "B")
    a = [e async for e in b.read(ORG_A)]
    c = [e async for e in b.read(ORG_B)]
    a[3] = c[3]  # org B's entry (valid for B) spliced into A's chain at the same seq
    res = await m.verify.verify(ORG_A, ListBackend(a))
    assert (res.result, res.first_bad_seq) == ("bad_record", 3)
    a2 = [e async for e in b.read(ORG_A)]
    a2[3] = replace(a2[3], chain_id=ORG_B)  # relabelled without rehash
    assert (await m.verify.verify(ORG_A, ListBackend(a2))).result == "bad_record"


async def test_concurrent_appends_to_two_orgs_do_not_interleave() -> None:
    m = mods()
    b = m.memory_backend.InMemoryChainBackend()
    await asyncio.gather(*[_append(b, ORG_A if k % 2 == 0 else ORG_B, 25, "A" if k % 2 == 0 else "B") for k in range(8)])
    for cid, tag in ((ORG_A, "A"), (ORG_B, "B")):
        rows = [e async for e in b.read(cid)]
        assert [e.seq for e in rows] == list(range(100))
        assert all(e.chain_id == cid and e.payload["org"] == tag for e in rows)
        assert (await m.verify.verify(cid, b)).result == "ok"


def test_threaded_appends_to_two_orgs_do_not_interleave() -> None:
    m = mods()
    b = m.memory_backend.InMemoryChainBackend()
    errors: list[BaseException] = []

    def work(cid: str, tag: str) -> None:
        try:
            run(_append(b, cid, 40, tag))
        except BaseException as exc:  # noqa: BLE001 - reported below
            errors.append(exc)

    threads = [threading.Thread(target=work, args=((ORG_A, "A") if k % 2 == 0 else (ORG_B, "B"))) for k in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert not errors
    for cid, tag in ((ORG_A, "A"), (ORG_B, "B")):
        rows = run(_collect(b, cid))
        assert [e.seq for e in rows] == list(range(160))
        assert all(e.payload["org"] == tag for e in rows)
        assert run(m.verify.verify(cid, b)).result == "ok"


async def _collect(b, cid):
    return [e async for e in b.read(cid)]


HOSTILE_IDS = [
    "intake:", "intake: ", "intake:a b", "intake:a\nb", "intake:a\x00b", "intake:١", "intake:" + "a" * 201,
    "engagement:../x", "engagement:x\n", "engagement:", "Engagement:x", "tenant:x", "", "intake", ":x",
    "intake:org'; DROP TABLE ledger_entries;--", "intake:<script>", "intake:a/b", "intake:\ud800",
]


@pytest.mark.parametrize("cid", HOSTILE_IDS)
async def test_hostile_chain_ids_are_refused_before_any_storage(cid: str) -> None:
    m = mods()
    b = m.memory_backend.InMemoryChainBackend()
    with pytest.raises(m.errors.CanonicalizationError):
        await b.append(cid, "policy.decision", "system", {"a": 1}, BASE_TS)
    assert await b.record_count("intake:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa") == 0


@pytest.mark.parametrize("kind,actor", [("Policy", "system"), ("policy decision", "system"), ("", "system"),
                                         ("policy.decision", ""), ("policy.decision", "user: x"), ("policy.decision", "a\nb")])
async def test_hostile_kind_and_actor_refused(kind: str, actor: str) -> None:
    m = mods()
    with pytest.raises(m.errors.CanonicalizationError):
        await m.memory_backend.InMemoryChainBackend().append(ORG_A, kind, actor, {}, BASE_TS)


async def test_naive_timestamp_refused() -> None:
    from datetime import datetime

    m = mods()
    with pytest.raises((m.errors.CanonicalizationError, ValueError)):
        await m.memory_backend.InMemoryChainBackend().append(ORG_A, "policy.decision", "system", {}, datetime(2026, 1, 1))


@pytest.mark.integration
def test_postgres_two_org_intake_chains_concurrent_and_isolated(request: pytest.FixtureRequest) -> None:
    from ledger_r1_support import pg_admin_fetch, pg_backend, pg_scratch

    db = pg_scratch(request)
    m = mods()
    tag = uuid.uuid4().hex
    names = [f"intake:{uuid.uuid4()}", f"intake:{uuid.uuid4()}"]
    chains = dict(zip(names, ("A", "B"), strict=True))

    async def go():
        engine, backend = await pg_backend(db)
        try:
            await asyncio.gather(*[_append(backend, names[k % 2], 15, f"{chains[names[k % 2]]}{tag}") for k in range(8)])
            return {c: ([e async for e in backend.read(c)], await m.verify.verify(c, backend)) for c in names}
        finally:
            await engine.dispose()

    out = run(go())
    for c in names:
        rows, res = out[c]
        assert [e.seq for e in rows] == list(range(60)) and res.result == "ok"
        assert all(e.chain_id == c and e.payload["org"] == f"{chains[c]}{tag}" for e in rows)
    heads = pg_admin_fetch(db, "SELECT chain_id, seq FROM chain_heads WHERE chain_id = ANY($1::text[])", names)
    assert sorted((r["chain_id"], r["seq"]) for r in heads) == sorted((c, 59) for c in names)
    first = {c: out[c][0][0].prev_hash for c in names}
    assert first[names[0]] != first[names[1]]
