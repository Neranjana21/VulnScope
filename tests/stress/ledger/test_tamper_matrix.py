# ruff: noqa: E501
"""Stress (R1): ledger tamper matrix. docs/stress-tests.md Ledger "Tamper: edit, delete, insert,
reorder, truncate tail, fork. verify() must name the first bad index."; Slice 0 AC3.

Spec: docs/gates/task-b-design.md section 4 (result codes) and F13. Each case asserts the exact
code, ``first_bad_seq``, ``records`` (entries consumed by the walk including the offending one) and
``checkpoint_seq``. Chains are built with the stdlib reference oracle (ledger_r1_support), never by
the implementation under test; tampering is applied to a ListBackend double.

Owner decision 2026-11-23 (resolves a design-table gap): a NEGATIVE seq is malformed and reports
``bad_record``, never ``fork`` (design step 1 would say fork for seq < expected; the negative check
must come first). The reported index is the position or the stored value, either accepted.
"""
from __future__ import annotations

from dataclasses import replace
from datetime import timedelta

import pytest
from ledger_r1_support import (
    BASE_TS,
    SEED1,
    ListBackend,
    cascade,
    cp_over,
    flip_hex_char,
    load_signer,
    mods,
    ref_chain,
    ref_genesis,
    ref_hash,
    rehash,
    run,
    verifier_for,
)

CID = "engagement:3f2c9a10-7b1e-4c55-9d0a-6e1b2c3d4e5f"
OTHER = "engagement:99999999-9999-4999-8999-999999999999"
N = 10


async def _verify(entries, cp=None, with_verifier=True):
    m = mods()
    kw = {"verifier": verifier_for(SEED1)} if (cp is not None and with_verifier) else {}
    return await m.verify.verify(CID, ListBackend(entries), cp, **kw)


def _swap(es, i, j):
    es[i], es[j] = es[j], es[i]
    return es


def _move(es, src, dst):
    e = es.pop(src)
    es.insert(dst, e)
    return es


def _e(i=None):
    return ref_chain(CID, N)


def _foreign(es, at):
    foreign = ref_chain(OTHER, N)[at]
    es[at] = foreign
    return es


def _dup_valid(es, at):
    twin = rehash(es[at], payload={"i": at, "twin": True})
    es.insert(at + 1, twin)
    return es


def _insert_renumbered(es, at):
    new = rehash(es[at - 1], seq=at, prev_hash=es[at - 1].record_hash, payload={"inserted": True})
    shifted = [replace(x, seq=x.seq + 1) for x in es[at:]]
    return es[:at] + [new] + shifted


def _insert_dup_seq(es, at):
    new = rehash(es[at - 1], seq=at, prev_hash=es[at - 1].record_hash, payload={"inserted": True})
    return es[:at] + [new] + es[at:]


def _wrong_genesis(es):
    bad_prev = ref_genesis(OTHER)
    return [rehash(es[0], prev_hash=bad_prev)] + es[1:]


# name -> (builder, expected (result, first_bad_seq, records))
NO_CHECKPOINT = {
    "payload_edit_no_rehash": (lambda: [*_e()[:4], replace(_e()[4], payload={"i": 4, "evil": 1}), *_e()[5:]], ("bad_record", 4, 5)),
    "record_hash_replaced": (lambda: [*_e()[:4], replace(_e()[4], record_hash="ab" * 32), *_e()[5:]], ("bad_record", 4, 5)),
    "prev_hash_replaced": (lambda: [*_e()[:4], replace(_e()[4], prev_hash="cd" * 32), *_e()[5:]], ("bad_record", 4, 5)),
    "edit_and_rehash_only_that_record": (lambda: [*_e()[:4], rehash(_e()[4], payload={"i": 4, "evil": 1}), *_e()[5:]], ("bad_record", 5, 6)),
    "kind_edit": (lambda: [*_e()[:2], replace(_e()[2], kind="evidence"), *_e()[3:]], ("bad_record", 2, 3)),
    "actor_edit": (lambda: [*_e()[:6], replace(_e()[6], actor="user:mallory"), *_e()[7:]], ("bad_record", 6, 7)),
    "ts_edit": (lambda: [*_e()[:3], replace(_e()[3], ts=_e()[3].ts + timedelta(seconds=1)), *_e()[4:]], ("bad_record", 3, 4)),
    "ts_edit_one_microsecond": (lambda: [*_e()[:3], replace(_e()[3], ts=_e()[3].ts + timedelta(microseconds=1)), *_e()[4:]], ("bad_record", 3, 4)),
    "schema_version_edit": (lambda: [*_e()[:3], replace(_e()[3], schema_version=2), *_e()[4:]], ("bad_record", 3, 4)),
    "uppercase_record_hash": (lambda: [*_e()[:3], replace(_e()[3], record_hash=_e()[3].record_hash.upper()), *_e()[4:]], ("bad_record", 3, 4)),
    "short_prev_hash": (lambda: [*_e()[:3], replace(_e()[3], prev_hash=_e()[3].prev_hash[:63]), *_e()[4:]], ("bad_record", 3, 4)),
    "non_hex_record_hash": (lambda: [*_e()[:3], replace(_e()[3], record_hash="zz" * 32), *_e()[4:]], ("bad_record", 3, 4)),
    "float_in_payload_does_not_raise": (lambda: [*_e()[:5], replace(_e()[5], payload={"x": 1.5}), *_e()[6:]], ("bad_record", 5, 6)),
    "nan_in_payload_does_not_raise": (lambda: [*_e()[:5], replace(_e()[5], payload={"x": float("nan")}), *_e()[6:]], ("bad_record", 5, 6)),
    "bytes_in_payload_does_not_raise": (lambda: [*_e()[:5], replace(_e()[5], payload={"x": b"raw"}), *_e()[6:]], ("bad_record", 5, 6)),
    "delete_middle": (lambda: _e()[:4] + _e()[5:], ("bad_record", 4, 5)),
    "delete_head": (lambda: _e()[1:], ("bad_record", 0, 1)),
    "delete_two_adjacent_middle": (lambda: _e()[:3] + _e()[5:], ("bad_record", 3, 4)),
    "insert_renumbered_successors": (lambda: _insert_renumbered(_e(), 5), ("bad_record", 6, 7)),
    "insert_duplicate_seq_is_fork": (lambda: _insert_dup_seq(_e(), 5), ("fork", 5, 7)),
    "adjacent_swap": (lambda: _swap(_e(), 4, 5), ("bad_record", 4, 5)),
    "far_move": (lambda: _move(_e(), 2, 8), ("bad_record", 2, 3)),
    "duplicate_seq_both_valid_fork": (lambda: _dup_valid(_e(), 4), ("fork", 4, 6)),
    "foreign_chain_entry": (lambda: _foreign(_e(), 5), ("bad_record", 5, 6)),
    "wrong_genesis": (lambda: _wrong_genesis(_e()), ("bad_record", 0, 1)),
    "cascade_rewrite_undetectable_without_checkpoint": (lambda: cascade(_e(), 4, evil=1), ("ok", None, N)),
    "tail_truncate_undetectable_without_checkpoint": (lambda: _e()[:7], ("ok", None, 7)),
    "empty_chain_without_checkpoint": (lambda: [], ("ok", None, 0)),
    "pristine": (lambda: _e(), ("ok", None, N)),
}


@pytest.mark.parametrize("name", sorted(NO_CHECKPOINT))
async def test_tamper_without_checkpoint(name: str) -> None:
    build, (code, bad, records) = NO_CHECKPOINT[name]
    res = await _verify(build())
    assert (res.result, res.first_bad_seq, res.records) == (code, bad, records)
    assert res.checkpoint_seq is None


async def test_negative_seq_is_reported_not_ok_and_does_not_raise() -> None:
    es = _e()
    es[0] = rehash(es[0], seq=-1)
    res = await _verify(es)
    # Owner decision 2026-11-23: a negative seq is malformed, so bad_record (never fork). The
    # reported index is the offending position (0) or the stored value (-1); both are accepted.
    assert res.result == "bad_record"
    assert res.first_bad_seq in (-1, 0)
    assert res.records == 1


async def test_negative_seq_mid_chain_is_not_ok() -> None:
    es = _e()
    es[4] = rehash(es[4], seq=-5)
    res = await _verify(es)
    assert res.result == "bad_record"  # owner decision 2026-11-23 (not fork)
    assert res.first_bad_seq in (-5, 4) and res.records == 5


# ---- with a checkpoint (signed over the pristine head at seq N-1 unless stated)
WITH_CP = {
    "pristine_anchor_at_head": (lambda: _e(), 9, ("ok", None, N, 9)),
    "older_checkpoint_is_ok_with_coverage": (lambda: _e(), 4, ("ok", None, N, 4)),
    "tail_truncate_detected": (lambda: _e()[:7], 9, ("truncated", 7, 7, 9)),
    "truncate_to_exactly_checkpoint_is_ok": (lambda: _e()[:10], 9, ("ok", None, 10, 9)),
    "truncate_one_below_checkpoint": (lambda: _e()[:9], 9, ("truncated", 9, 9, 9)),
    "empty_chain_with_checkpoint": (lambda: [], 5, ("truncated", 0, 0, 5)),
    "full_cascade_rewrite_caught_only_by_anchor": (lambda: cascade(_e(), 4, evil=1), 9, ("bad_record", 9, N, 9)),
    "cascade_rewrite_below_older_anchor": (lambda: cascade(_e(), 4, evil=1), 6, ("bad_record", 6, N, 6)),
    "edit_before_anchor_caught_by_walk_first": (lambda: [*_e()[:4], replace(_e()[4], payload={"e": 1}), *_e()[5:]], 9, ("bad_record", 4, 5, None)),
    "delete_middle_with_anchor": (lambda: _e()[:4] + _e()[5:], 9, ("bad_record", 4, 5, None)),
}


@pytest.mark.parametrize("name", sorted(WITH_CP))
async def test_tamper_with_signed_checkpoint(name: str) -> None:
    build, cp_seq, (code, bad, records, cps) = WITH_CP[name]
    pristine = ref_chain(CID, N)
    res = await _verify(build(), cp_over(pristine, cp_seq))
    assert (res.result, res.first_bad_seq, res.records) == (code, bad, records)
    if cps is not None:
        assert res.checkpoint_seq == cps


async def test_unanchored_tail_length_is_visible() -> None:
    res = await _verify(_e(), cp_over(_e(), 4))
    assert res.records - res.checkpoint_seq - 1 == 5


def test_verify_never_raises_on_tampered_data_property() -> None:
    from hypothesis import HealthCheck, given, settings
    from hypothesis import strategies as st

    fields = st.sampled_from(["payload", "kind", "actor", "ts", "prev_hash", "record_hash", "seq", "chain_id"])

    @given(idx=st.integers(0, N - 1), field=fields, drop=st.booleans())
    @settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    def prop(idx: int, field: str, drop: bool) -> None:
        es = _e()
        e = es[idx]
        new = {
            "payload": {"mut": idx}, "kind": "scan.x", "actor": "user:z", "ts": e.ts + timedelta(seconds=7),
            "prev_hash": "0" * 64, "record_hash": "1" * 64, "seq": e.seq + 100, "chain_id": OTHER,
        }[field]
        es[idx] = replace(e, **{field: new})
        if drop:
            del es[(idx + 3) % len(es)]
        res = run(_verify(es))
        assert res.result in ("bad_record", "fork", "truncated", "ok")
        # Property: any single-field mutation without rehash is NEVER reported ok (no checkpoint needed).
        if not drop:
            assert res.result != "ok"
            assert res.first_bad_seq == idx

    prop()


async def test_reference_oracle_is_self_consistent() -> None:
    es = ref_chain(CID, 3)
    assert es[0].prev_hash == ref_genesis(CID)
    assert all(ref_hash(e) == e.record_hash for e in es)
    assert es[1].prev_hash == es[0].record_hash
    assert BASE_TS.tzinfo is not None


# ---- Postgres variant: tamper as the ADMIN role (owner), verify through the real backend
pytestmark_pg = pytest.mark.integration


@pytest.mark.integration
def test_postgres_admin_tamper_edit_delete_truncate_cascade(request: pytest.FixtureRequest) -> None:
    from ledger_r1_support import pg_admin_sql, pg_backend, pg_scratch, sql_lit

    db = pg_scratch(request)
    import uuid

    m = mods()
    ids = {k: f"engagement:{uuid.uuid4()}" for k in ("edit", "delete", "trunc", "cascade")}

    async def seed():
        engine, backend = await pg_backend(db)
        try:
            for cid in ids.values():
                for i in range(10):
                    await backend.append(cid, "policy.decision", "system", {"i": i}, BASE_TS + timedelta(seconds=i))
                assert (await m.verify.verify(cid, backend)).result == "ok"
        finally:
            await engine.dispose()

    run(seed())
    triggers = "ledger_entries_no_mutate"
    pg_admin_sql(db, f"ALTER TABLE ledger_entries DISABLE TRIGGER {triggers}")
    try:
        pg_admin_sql(
            db,
            f"UPDATE ledger_entries SET payload = '{{\"i\": 999}}'::json WHERE chain_id = {sql_lit(ids['edit'])} AND seq = 4",
            f"DELETE FROM ledger_entries WHERE chain_id = {sql_lit(ids['delete'])} AND seq = 4",
            f"DELETE FROM ledger_entries WHERE chain_id = {sql_lit(ids['trunc'])} AND seq >= 7",
        )
        # cascade: rewrite seq 4..9 of the 'cascade' chain with new payload, recomputed links/hashes
        from ledger_r1_support import pg_admin_fetch

        from vulnscope.ledger.types import LedgerEntry

        rows = pg_admin_fetch(
            db, "SELECT seq, kind, actor, payload::text AS p, ts, prev_hash, record_hash FROM ledger_entries "
                "WHERE chain_id = $1 ORDER BY seq", ids["cascade"])
        import json
        orig = [LedgerEntry(1, ids["cascade"], r["seq"], r["kind"], r["actor"], json.loads(r["p"]), r["ts"], r["prev_hash"], r["record_hash"]) for r in rows]
        orig_cp = ref_checkpoint_for(orig, 9)
        new = cascade(orig, 4, evil=1)
        stmts = [
            f"UPDATE ledger_entries SET payload = {sql_lit(json.dumps(e.payload))}::json, prev_hash = {sql_lit(e.prev_hash)}, "
            f"record_hash = {sql_lit(e.record_hash)} WHERE chain_id = {sql_lit(ids['cascade'])} AND seq = {e.seq}"
            for e in new[4:]
        ]
        pg_admin_sql(db, *stmts)
    finally:
        pg_admin_sql(db, f"ALTER TABLE ledger_entries ENABLE ALWAYS TRIGGER {triggers}")

    async def check():
        engine, backend = await pg_backend(db)
        try:
            v = verifier_for(SEED1)
            r_edit = await m.verify.verify(ids["edit"], backend)
            r_del = await m.verify.verify(ids["delete"], backend)
            r_trunc_plain = await m.verify.verify(ids["trunc"], backend)
            r_casc_plain = await m.verify.verify(ids["cascade"], backend)
            r_casc_cp = await m.verify.verify(ids["cascade"], backend, orig_cp, verifier=v)
            return r_edit, r_del, r_trunc_plain, r_casc_plain, r_casc_cp
        finally:
            await engine.dispose()

    r_edit, r_del, r_trunc_plain, r_casc_plain, r_casc_cp = run(check())
    assert (r_edit.result, r_edit.first_bad_seq) == ("bad_record", 4)
    assert (r_del.result, r_del.first_bad_seq) == ("bad_record", 4)
    assert r_trunc_plain.result == "ok" and r_trunc_plain.records == 7  # limitation without checkpoint
    assert r_casc_plain.result == "ok"  # limitation without checkpoint
    assert (r_casc_cp.result, r_casc_cp.first_bad_seq) == ("bad_record", 9)


def ref_checkpoint_for(entries, seq):
    from ledger_r1_support import ref_checkpoint

    e = entries[seq]
    return ref_checkpoint(SEED1, e.chain_id, e.seq, e.record_hash, BASE_TS + timedelta(hours=1))


@pytest.mark.integration
def test_postgres_truncation_vs_checkpoint(request: pytest.FixtureRequest, tmp_path) -> None:
    from ledger_r1_support import pg_admin_sql, pg_backend, pg_scratch, sql_lit

    db = pg_scratch(request)
    import uuid

    m = mods()
    cid = f"engagement:{uuid.uuid4()}"
    signer = load_signer(tmp_path, SEED1)

    async def seed():
        engine, backend = await pg_backend(db)
        try:
            for i in range(10):
                await backend.append(cid, "policy.decision", "system", {"i": i}, BASE_TS + timedelta(seconds=i))
            head = await backend.head(cid)
            return m.checkpoint.sign_checkpoint(cid, head.seq, head.record_hash, BASE_TS + timedelta(hours=1), signer)
        finally:
            await engine.dispose()

    cp = run(seed())
    pg_admin_sql(db, "ALTER TABLE ledger_entries DISABLE TRIGGER ledger_entries_no_mutate")
    try:
        pg_admin_sql(db, f"DELETE FROM ledger_entries WHERE chain_id = {sql_lit(cid)} AND seq >= 7")
    finally:
        pg_admin_sql(db, "ALTER TABLE ledger_entries ENABLE ALWAYS TRIGGER ledger_entries_no_mutate")

    async def check():
        engine, backend = await pg_backend(db)
        try:
            return await m.verify.verify(cid, backend, cp, verifier=verifier_for(SEED1))
        finally:
            await engine.dispose()

    res = run(check())
    assert (res.result, res.first_bad_seq, res.records, res.checkpoint_seq) == ("truncated", 7, 7, 9)


def test_flip_helper_changes_exactly_one_char() -> None:
    s = "ab" * 32
    t = flip_hex_char(s, 5)
    assert sum(a != b for a, b in zip(s, t, strict=True)) == 1 and len(t) == 64
