# ruff: noqa: E501
"""Stress (R1): forged, stale, newer and malformed checkpoints; checkpoint cadence and signing rules.
docs/stress-tests.md Ledger "Truncation vs checkpoint; forged checkpoint signature; checkpoint older
than the data"; Slice 0 AC3. Spec: docs/gates/task-b-design.md sections 4 and 5, F2, F10, F11, F12.

Rules pinned here: a checkpoint that is not authentic RAISES ``CheckpointRejected`` (never a result
code, never ``ok``); order of caller-error checks is no_verifier, wrong_chain, bad_signature; the
signing path never signs a chain it has not walked (``CheckpointRefused``); sink is written BEFORE
the store; forged rows in the checkpoints table cannot block anchoring. Seeds are built in code
(``bytes(range(32))`` etc.); nothing secret is stored.
"""
from __future__ import annotations

import uuid
from dataclasses import replace
from datetime import timedelta

import pytest
from ledger_r1_support import (
    BASE_TS,
    SEED1,
    SEED2,
    SEED3,
    ListBackend,
    cp_over,
    flip_hex_char,
    golden,
    load_signer,
    mods,
    public_hex,
    ref_chain,
    ref_checkpoint,
    rehash,
    run,
    verifier_for,
)

from vulnscope.ledger.types import Checkpoint

CID = "engagement:3f2c9a10-7b1e-4c55-9d0a-6e1b2c3d4e5f"
OTHER = "engagement:99999999-9999-4999-8999-999999999999"
TS = BASE_TS + timedelta(hours=1)


async def _verify(entries, cp, seed=SEED1, with_verifier=True):
    kw = {"verifier": verifier_for(seed)} if with_verifier else {}
    return await mods().verify.verify(CID, ListBackend(entries), cp, **kw)


async def _expect_rejected(entries, cp, reasons, **kw):
    err = mods().errors.CheckpointRejected
    with pytest.raises(err) as info:
        await _verify(entries, cp, **kw)
    assert info.value.reason in reasons
    return info.value


# ------------------------------------------------------------------ authenticity
async def test_valid_checkpoint_anchors_clean_chain() -> None:
    es = ref_chain(CID, 10)
    res = await _verify(es, cp_over(es, 9))
    assert (res.result, res.first_bad_seq, res.records, res.checkpoint_seq) == ("ok", None, 10, 9)


async def test_missing_verifier_is_rejected_not_trusted() -> None:
    es = ref_chain(CID, 10)
    await _expect_rejected(es, cp_over(es, 9), {"no_verifier"}, with_verifier=False)


async def test_foreign_chain_checkpoint_is_wrong_chain() -> None:
    es = ref_chain(CID, 10)
    other = ref_chain(OTHER, 10)
    await _expect_rejected(es, cp_over(other, 9), {"wrong_chain"})


@pytest.mark.parametrize("field", ["seq_minus", "seq_plus", "head_first", "head_last", "ts_plus_us"])
async def test_any_field_flip_invalidates_signature(field: str) -> None:
    es = ref_chain(CID, 10)
    cp = cp_over(es, 5)
    bad = {
        "seq_minus": replace(cp, seq=cp.seq - 1), "seq_plus": replace(cp, seq=cp.seq + 1),
        "head_first": replace(cp, head_hash=flip_hex_char(cp.head_hash, 0)),
        "head_last": replace(cp, head_hash=flip_hex_char(cp.head_hash, 63)),
        "ts_plus_us": replace(cp, ts=cp.ts + timedelta(microseconds=1)),
    }[field]
    await _expect_rejected(es, bad, {"bad_signature"})


async def test_every_signature_byte_flip_is_rejected() -> None:
    es = ref_chain(CID, 10)
    cp = cp_over(es, 9)
    raw = bytes.fromhex(cp.signature)
    assert len(raw) == 64
    for i in range(64):
        flipped = bytearray(raw)
        flipped[i] ^= 0x01
        await _expect_rejected(es, replace(cp, signature=bytes(flipped).hex()), {"bad_signature", "malformed"})


@pytest.mark.parametrize("variant", ["empty", "non_hex", "short", "long", "uppercase", "newline", "space"])
async def test_malformed_signature_strings_raise(variant: str) -> None:
    es = ref_chain(CID, 10)
    good = cp_over(es, 9).signature
    sig = {"empty": "", "non_hex": "zz" * 64, "short": good[:126], "long": good + "00",
           "uppercase": good.upper(), "newline": good + "\n", "space": good + " "}[variant]
    await _expect_rejected(es, replace(cp_over(es, 9), signature=sig), {"bad_signature", "malformed"})


async def test_wrong_key_signature_is_rejected() -> None:
    es = ref_chain(CID, 10)
    await _expect_rejected(es, cp_over(es, 9, seed=SEED2), {"bad_signature"})  # verifier holds SEED1


async def test_forged_checkpoint_over_a_forged_chain_is_still_rejected() -> None:
    forged = ref_chain(CID, 10)
    from ledger_r1_support import cascade
    rewritten = cascade(forged, 0, evil=1)
    await _expect_rejected(rewritten, cp_over(rewritten, 9, seed=SEED3), {"bad_signature"})


def test_check_signature_returns_bool_and_never_raises_on_garbage() -> None:
    m = mods()
    es = ref_chain(CID, 10)
    good = cp_over(es, 9)
    v = verifier_for(SEED1)
    assert m.checkpoint.check_signature(good, v) is True
    for sig in ("", "zz", "ab" * 64, good.signature.upper(), good.signature[:-2]):
        assert m.checkpoint.check_signature(replace(good, signature=sig), v) is False
    assert m.checkpoint.check_signature(cp_over(es, 9, seed=SEED2), v) is False


# ------------------------------------------------------------------ older / newer / replay
async def test_older_checkpoint_is_ok_with_coverage_reported() -> None:
    es = ref_chain(CID, 10)
    res = await _verify(es, cp_over(es, 3))
    assert (res.result, res.records, res.checkpoint_seq) == ("ok", 10, 3)


async def test_newer_checkpoint_than_data_is_truncated() -> None:
    long = ref_chain(CID, 15)
    cp = cp_over(long, 12)
    res = await _verify(long[:10], cp)
    assert (res.result, res.first_bad_seq, res.records, res.checkpoint_seq) == ("truncated", 10, 10, 12)


async def test_replay_of_older_genuine_checkpoint_after_truncation_is_documented_limitation() -> None:
    """ADR-0003 / design section 5: truncating AND presenting an older genuine checkpoint is not
    detectable; only the latest anchor counts. This test pins the documented limit (no silent change)."""
    es = ref_chain(CID, 10)
    old = cp_over(es, 4)
    res = await _verify(es[:5], old)
    assert (res.result, res.checkpoint_seq) == ("ok", 4)


async def test_checkpoint_at_seq_zero_and_empty_chain() -> None:
    es = ref_chain(CID, 1)
    res = await _verify(es, cp_over(es, 0))
    assert (res.result, res.records, res.checkpoint_seq) == ("ok", 1, 0)
    res = await _verify([], cp_over(es, 0))
    assert (res.result, res.first_bad_seq, res.records) == ("truncated", 0, 0)


# ------------------------------------------------------------------ key rotation
async def test_two_key_rotation_verifies_old_and_new_and_rejects_third() -> None:
    m = mods()
    es = ref_chain(CID, 10)
    multi = m.signer.MultiKeyVerifier([verifier_for(SEED2), verifier_for(SEED1)])
    for seed in (SEED1, SEED2):
        res = await m.verify.verify(CID, ListBackend(es), cp_over(es, 9, seed=seed), verifier=multi)
        assert res.result == "ok"
    with pytest.raises(m.errors.CheckpointRejected) as info:
        await m.verify.verify(CID, ListBackend(es), cp_over(es, 9, seed=SEED3), verifier=multi)
    assert info.value.reason == "bad_signature"


# ------------------------------------------------------------------ message format and parsing
def test_checkpoint_message_matches_golden_and_is_domain_separated() -> None:
    m = mods()
    g = golden("checkpoint_vectors.json")
    from datetime import datetime
    for c in g["key1"]:
        ts = datetime.fromisoformat(c["ts_input"])
        msg = m.checkpoint.checkpoint_message(c["chain_id"], c["seq"], c["head_hash"], ts)
        assert msg.hex() == c["message_hex"]
        assert msg.startswith(b"vulnscope-checkpoint-v1\n")
        # a record-hash input starts with 64 lowercase-hex ASCII bytes; a checkpoint message never does
        assert not set(msg[:64]) <= set(b"0123456789abcdef")


def test_sign_checkpoint_matches_golden_signature(tmp_path) -> None:
    m = mods()
    g = golden("checkpoint_vectors.json")
    from datetime import datetime
    signer = load_signer(tmp_path, SEED1)
    assert signer.public_key_hex == g["key1_public_hex"] == public_hex(SEED1)
    for c in g["key1"]:
        cp = m.checkpoint.sign_checkpoint(c["chain_id"], c["seq"], c["head_hash"], datetime.fromisoformat(c["ts_input"]), signer)
        assert cp.signature == c["signature_hex"]


def test_line_roundtrip_and_hostile_text_is_malformed_with_fixed_message() -> None:
    m = mods()
    es = ref_chain(CID, 10)
    cp = cp_over(es, 9)
    assert m.checkpoint.checkpoint_from_text(m.checkpoint.checkpoint_to_line(cp)) == cp
    canary = "CANARY-" + uuid.uuid4().hex
    good = m.checkpoint.checkpoint_to_line(cp).strip()
    hostile = [
        "x" * 100_000 + canary, canary + "\x00", "[" * 10_000 + canary, "[]", "null", "5", '"' + canary + '"',
        good.replace(cp.chain_id, canary), good.replace('"seq":9', '"seq":"9"'), good.replace('"seq":9', '"seq":9.0'),
        good[:-1] + f',"extra":"{canary}"}}', good.replace(cp.head_hash, cp.head_hash.upper()),
        good.replace("Z\"", "+00:00\""), "\ud800" + canary, "{" + canary,
    ]
    for text in hostile:
        with pytest.raises(m.errors.CheckpointRejected) as info:
            m.checkpoint.checkpoint_from_text(text)
        assert info.value.reason == "malformed"
        assert canary not in str(info.value) and canary not in repr(info.value)
        assert info.value.__cause__ is None or canary not in repr(info.value.__cause__)


# ------------------------------------------------------------------ maybe_checkpoint
class _Sink:
    def __init__(self, order=None, fail=False):
        self.written, self.order, self.fail = [], order if order is not None else [], fail

    async def write(self, cp):
        self.order.append("sink")
        if self.fail:
            raise RuntimeError("disk full")
        self.written.append(cp)


def _ordered_store(order):
    m = mods()

    class Store(m.checkpoint.InMemoryCheckpointStore):
        async def save(self, cp):
            order.append("store")
            return await super().save(cp)

    return Store()


async def _filled(n, cid=CID):
    m = mods()
    b = m.memory_backend.InMemoryChainBackend()
    for i in range(n):
        await b.append(cid, "policy.decision", "system", {"i": i}, BASE_TS + timedelta(seconds=i))
    return b


async def test_cadence_due_at_100_not_at_99_and_force(tmp_path) -> None:
    m = mods()
    signer = load_signer(tmp_path, SEED1)
    for n, force, expect in ((99, False, None), (100, False, 99), (99, True, 98), (1, True, 0)):
        b = await _filled(n)
        cp = await m.checkpoint.maybe_checkpoint(CID, b, signer, store=m.checkpoint.InMemoryCheckpointStore(), ts=TS, force=force)
        assert (cp.seq if cp else None) == expect
        if cp:
            assert cp.head_hash == (await b.head(CID)).record_hash
            assert m.checkpoint.check_signature(cp, verifier_for(SEED1))
    empty = await m.checkpoint.maybe_checkpoint(CID, m.memory_backend.InMemoryChainBackend(), signer, store=m.checkpoint.InMemoryCheckpointStore(), ts=TS, force=True)
    assert empty is None


async def test_second_checkpoint_walks_only_the_new_segment(tmp_path) -> None:
    m = mods()
    signer = load_signer(tmp_path, SEED1)
    es = ref_chain(CID, 100)
    store = m.checkpoint.InMemoryCheckpointStore()
    lb = ListBackend(es)
    first = await m.checkpoint.maybe_checkpoint(CID, lb, signer, store=store, ts=TS)
    assert first.seq == 99
    lb.entries = ref_chain(CID, 200)
    lb.read_count = 0
    second = await m.checkpoint.maybe_checkpoint(CID, lb, signer, store=store, ts=TS)
    assert second.seq == 199
    assert lb.read_count <= 110, "incremental walk must be O(interval), not O(n)"


async def test_refuses_to_sign_a_tampered_segment_and_writes_nothing(tmp_path) -> None:
    m = mods()
    signer = load_signer(tmp_path, SEED1)
    es = ref_chain(CID, 150)
    es[120] = replace(es[120], payload={"evil": 1})
    store, sink = m.checkpoint.InMemoryCheckpointStore(), _Sink()
    with pytest.raises(m.errors.CheckpointRefused) as info:
        await m.checkpoint.maybe_checkpoint(CID, ListBackend(es), signer, store=store, sink=sink, ts=TS, force=True)
    assert info.value.reason == "chain_not_verified"
    assert sink.written == [] and await store.latest(CID) is None


async def test_checkpoint_never_launders_a_cascade_rewrite_under_an_existing_anchor(tmp_path) -> None:
    from ledger_r1_support import cascade
    m = mods()
    signer = load_signer(tmp_path, SEED1)
    es = ref_chain(CID, 200)
    store = m.checkpoint.InMemoryCheckpointStore()
    await store.save(cp_over(es, 99))
    rewritten = cascade(es, 50, evil=1)  # rewritten across the existing anchor
    with pytest.raises(m.errors.CheckpointRefused):
        await m.checkpoint.maybe_checkpoint(CID, ListBackend(rewritten), signer, store=store, ts=TS, force=True)


async def test_sink_is_written_before_store_and_sink_failure_saves_nothing(tmp_path) -> None:
    m = mods()
    signer = load_signer(tmp_path, SEED1)
    order: list[str] = []
    store, sink = _ordered_store(order), _Sink(order)
    await m.checkpoint.maybe_checkpoint(CID, await _filled(100), signer, store=store, sink=sink, ts=TS)
    assert order == ["sink", "store"]
    order2: list[str] = []
    store2, sink2 = _ordered_store(order2), _Sink(order2, fail=True)
    with pytest.raises(RuntimeError):
        await m.checkpoint.maybe_checkpoint(CID, await _filled(100), signer, store=store2, sink=sink2, ts=TS)
    assert order2 == ["sink"] and await store2.latest(CID) is None


async def test_forged_high_seq_rows_cannot_block_anchoring(tmp_path) -> None:
    m = mods()
    signer = load_signer(tmp_path, SEED1)
    b = await _filled(150)
    store = m.checkpoint.InMemoryCheckpointStore()
    await store.save(Checkpoint(CID, 5000, "ab" * 32, TS, "cd" * 64))  # garbage signature
    await store.save(ref_checkpoint(SEED3, CID, 9000, "ef" * 32, TS))  # well-formed, wrong key
    cp = await m.checkpoint.maybe_checkpoint(CID, b, signer, store=store, ts=TS, force=True)
    assert cp is not None and cp.seq == 149
    assert m.checkpoint.check_signature(cp, verifier_for(SEED1))
    base, invalid = await store.latest_valid(CID, verifier_for(SEED1))
    assert base.seq == 149 and invalid == 2


async def test_signs_the_walked_tail_even_if_chain_grows_during_the_walk(tmp_path) -> None:
    m = mods()
    signer = load_signer(tmp_path, SEED1)
    inner = await _filled(100)

    class Race:
        raced = False

        async def append(self, *a, **k):
            return await inner.append(*a, **k)

        async def head(self, cid):
            return await inner.head(cid)

        async def record_count(self, cid):
            return await inner.record_count(cid)

        async def read(self, cid, start_seq=0, limit=None):
            if not Race.raced:
                Race.raced = True
                for i in range(5):
                    await inner.append(CID, "policy.decision", "system", {"late": i}, TS)
            async for e in inner.read(cid, start_seq, limit):
                yield e

    cp = await m.checkpoint.maybe_checkpoint(CID, Race(), signer, store=m.checkpoint.InMemoryCheckpointStore(), ts=TS)
    entries = [e async for e in inner.read(CID)]
    assert cp is not None and len(entries) == 105
    assert cp.seq == 99, "only the segment that was actually walked (up to the head seen at call time) may be signed"
    assert cp.head_hash == entries[cp.seq].record_hash, "must sign a (seq, hash) pair of the same entry"


async def test_hostile_tamper_inside_walked_segment_property(tmp_path) -> None:
    """Every single-entry corruption inside the segment makes maybe_checkpoint refuse (sampled)."""
    m = mods()
    signer = load_signer(tmp_path, SEED1)
    for idx in (0, 1, 50, 98, 99):
        es = ref_chain(CID, 100)
        # rehash-only edits are caught at the successor's linkage; the LAST entry has none (a tail
        # edit with a correct self-hash is undetectable without an anchor, design section 4)
        es[idx] = rehash(es[idx], payload={"evil": idx}) if idx % 2 and idx != 99 else replace(es[idx], payload={"evil": idx})
        with pytest.raises(m.errors.CheckpointRefused):
            await m.checkpoint.maybe_checkpoint(CID, ListBackend(es), signer, store=m.checkpoint.InMemoryCheckpointStore(), ts=TS)


# ------------------------------------------------------------------ Postgres: forged row in the real table
@pytest.mark.integration
def test_postgres_forged_high_seq_row_in_checkpoints_table(request: pytest.FixtureRequest, tmp_path) -> None:
    from ledger_r1_support import pg_backend, pg_scratch

    db = pg_scratch(request)
    m = mods()
    cid = f"engagement:{uuid.uuid4()}"
    signer = load_signer(tmp_path, SEED1)

    async def go():
        from vulnscope.ledger.postgres_backend import PostgresCheckpointStore

        engine, backend = await pg_backend(db)
        try:
            for i in range(120):
                await backend.append(cid, "policy.decision", "system", {"i": i}, BASE_TS + timedelta(seconds=i))
            store = PostgresCheckpointStore(engine)
            await store.save(Checkpoint(cid, 5000, "ab" * 32, TS, "cd" * 64))  # app role may INSERT
            cp = await m.checkpoint.maybe_checkpoint(cid, backend, signer, store=store, ts=TS)
            base, invalid = await store.latest_valid(cid, verifier_for(SEED1))
            res = await m.verify.verify(cid, backend, cp, verifier=verifier_for(SEED1))
            return cp, base, invalid, res
        finally:
            await engine.dispose()

    cp, base, invalid, res = run(go())
    assert cp is not None and cp.seq == 119 and base.seq == 119 and invalid == 1
    assert (res.result, res.checkpoint_seq, res.records) == ("ok", 119, 120)
