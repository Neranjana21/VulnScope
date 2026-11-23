# ruff: noqa: E501
"""Stress (R1): Task B against the cross-checked golden vectors (tests/fixtures/ledger_golden/).
Slice 0 AC4 hash half; ADR-0003 "changing it requires a new ledger version". Provenance and the
independent second-engine check: docs/gates/task-b-r1-vectors-crosscheck.md. Vector files are
read-only for the implementer.

Part 1 (vectors vs the stdlib reference oracle) needs no production code and is green now: it proves
the fixtures are self-consistent. Part 2 runs the same vectors through ``vulnscope.ledger.*``.
"""
from __future__ import annotations

import json
import re
from datetime import UTC, datetime

import pytest
from ledger_r1_support import (
    SEED1,
    SEED2,
    golden,
    load_signer,
    mods,
    public_hex,
    ref_canon,
    ref_genesis,
    ref_sha,
    ref_ts,
)

CV = golden("canonical_vectors.json")["vectors"]
TSV = golden("ts_vectors.json")["vectors"]
HV = golden("hash_vectors.json")
CPV = golden("checkpoint_vectors.json")
NEG = golden("negative_vectors.json")["vectors"]


# ------------------------------------------------------------------ part 1: fixtures vs reference
@pytest.mark.parametrize("v", CV, ids=lambda v: v["name"])
def test_fixture_canonical_matches_reference(v) -> None:
    b = ref_canon(json.loads(v["input_json"]))
    assert b.decode("utf-8") == v["canonical_utf8"] and b.hex() == v["canonical_hex"] and ref_sha(b) == v["sha256_hex"]


def test_fixture_chain_is_self_consistent_and_alternatives_differ() -> None:
    prev = ref_genesis(HV["chain_id"])
    for e in HV["entries"]:
        assert e["prev_hash"] == prev
        doc = json.loads(e["entry_document_canonical_utf8"])
        assert ref_sha(e["prev_hash"].encode("ascii") + ref_canon(doc)) == e["record_hash"]
        prev = e["record_hash"]
    assert all(h != HV["entries"][0]["record_hash"] for h in HV["wrong_interpretations_of_entry_0"].values())


# ------------------------------------------------------------------ part 2: production code
@pytest.mark.parametrize("v", CV, ids=lambda v: v["name"])
def test_canonical_json_matches_golden(v) -> None:
    b = mods().canonical.canonical_json(json.loads(v["input_json"]))
    assert b.hex() == v["canonical_hex"] and b.decode("utf-8") == v["canonical_utf8"]
    assert ref_sha(b) == v["sha256_hex"]


@pytest.mark.parametrize("v", TSV, ids=lambda v: v["ts_canonical"])
def test_format_and_parse_ts_match_golden(v) -> None:
    c = mods().canonical
    ts = datetime.fromisoformat(v["ts_input"])
    assert c.format_ts(ts) == v["ts_canonical"] == ref_ts(ts)
    back = c.parse_ts(v["ts_canonical"])
    assert back.utcoffset().total_seconds() == 0 and back == ts


def test_genesis_hashes_match_golden() -> None:
    for g in HV["genesis"]:
        assert mods().canonical.genesis_hash(g["chain_id"]) == g["genesis_hash"]


def _kwargs(e) -> dict:
    return dict(schema_version=HV["schema_version"], chain_id=HV["chain_id"], seq=e["seq"], kind=e["kind"],
                actor=e["actor"], payload=json.loads(e["payload_json"]), ts=datetime.fromisoformat(e["ts_input"]),
                prev_hash=e["prev_hash"])


@pytest.mark.parametrize("i", range(len(HV["entries"])))
def test_entry_document_and_record_hash_match_golden(i: int) -> None:
    c = mods().canonical
    e = HV["entries"][i]
    doc = c.entry_document(**_kwargs(e))
    assert c.canonical_json(doc).decode("utf-8") == e["entry_document_canonical_utf8"]
    assert c.compute_record_hash(**_kwargs(e)) == e["record_hash"]


def test_entry_record_hash_ignores_the_stored_hash_field() -> None:
    from vulnscope.ledger.types import LedgerEntry

    c = mods().canonical
    for e in HV["entries"]:
        k = _kwargs(e)
        entry = LedgerEntry(**k, record_hash="0" * 64)
        assert c.entry_record_hash(entry) == e["record_hash"]


def test_record_hash_is_not_any_of_the_wrong_interpretations() -> None:
    c = mods().canonical
    got = c.compute_record_hash(**_kwargs(HV["entries"][0]))
    assert got not in set(HV["wrong_interpretations_of_entry_0"].values())


def test_backend_built_chain_reproduces_golden_hashes() -> None:
    from ledger_r1_support import run

    m = mods()
    b = m.memory_backend.InMemoryChainBackend()

    async def go():
        out = []
        for e in HV["entries"]:
            k = _kwargs(e)
            out.append(await b.append(k["chain_id"], k["kind"], k["actor"], k["payload"], k["ts"]))
        return out

    got = run(go())
    assert [x.record_hash for x in got] == [e["record_hash"] for e in HV["entries"]]
    assert [x.prev_hash for x in got] == [e["prev_hash"] for e in HV["entries"]]


def test_checkpoint_public_keys_and_signatures_match_golden(tmp_path) -> None:
    m = mods()
    assert CPV["key1_public_hex"] == public_hex(SEED1) and CPV["key2_public_hex"] == public_hex(SEED2)
    s1, s2 = load_signer(tmp_path, SEED1, "k1"), load_signer(tmp_path, SEED2, "k2")
    assert s1.public_key_hex == CPV["key1_public_hex"] and s2.public_key_hex == CPV["key2_public_hex"]
    for key, signer in (("key1", s1), ("key2", s2)):
        for c in CPV[key]:
            ts = datetime.fromisoformat(c["ts_input"])
            assert m.checkpoint.checkpoint_message(c["chain_id"], c["seq"], c["head_hash"], ts).hex() == c["message_hex"]
            cp = m.checkpoint.sign_checkpoint(c["chain_id"], c["seq"], c["head_hash"], ts, signer)
            assert cp.signature == c["signature_hex"] and re.fullmatch(r"[0-9a-f]{128}", cp.signature)
            assert m.checkpoint.check_signature(cp, m.signer.Ed25519PublicVerifier.from_hex(CPV[f"{key}_public_hex"]))
    # a key1 signature never verifies under key2
    c0 = CPV["key1"][0]
    cp = m.checkpoint.sign_checkpoint(c0["chain_id"], c0["seq"], c0["head_hash"], datetime.fromisoformat(c0["ts_input"]), s1)
    assert not m.checkpoint.check_signature(cp, m.signer.Ed25519PublicVerifier.from_hex(CPV["key2_public_hex"]))


def _neg_value(v):
    if "input_json" in v:
        return json.loads(v["input_json"])
    gen, py = v.get("gen"), v.get("python")
    if gen == "depth":
        root: dict = {}
        cur = root
        for _ in range(v["n"] - 1):
            cur["a"] = {}
            cur = cur["a"]
        return root
    if gen == "bytes":
        return {"a": "x" * v["n"]}
    if gen == "chain201":
        return "engagement:" + "a" * 201
    return {"nan": float("nan"), "inf": float("inf"), "int_key": {1: "a"}, "bytes": {"a": b"x"},
            "datetime": {"a": datetime(2026, 1, 1, tzinfo=UTC)}, "naive": datetime(2026, 1, 1)}[py]


@pytest.mark.parametrize("v", NEG, ids=lambda v: v["name"])
def test_negative_vectors_raise_canonicalization_error(v) -> None:
    m = mods()
    c, err = m.canonical, m.errors.CanonicalizationError
    value = _neg_value(v)
    call = {
        "canonical_json": lambda: c.canonical_json(value),
        "normalize_payload": lambda: c.normalize_payload(value),
        "format_ts": lambda: c.format_ts(value),
        "chain_id": lambda: c.validate_chain_id(value),
        "kind": lambda: c.validate_kind(value),
        "actor": lambda: c.validate_actor(value),
        "parse_ts": lambda: c.parse_ts(value),
        "prev_hash": lambda: c.compute_record_hash(
            schema_version=1, chain_id="engagement:x", seq=0, kind="evidence", actor="system", payload={},
            ts=datetime(2026, 1, 1, tzinfo=UTC), prev_hash=value),
    }[v["kind"]]
    with pytest.raises(err):
        call()


def test_sixteen_nested_containers_are_accepted_by_the_strict_path() -> None:
    """Boundary pair for depth_17_root_counts_as_1. Owner decision 2026-11-23: the root payload dict
    counts as depth 1, so 16 nested containers (root + 15) are accepted and 17 are rejected."""
    c = mods().canonical
    root: dict = {}
    cur = root
    for _ in range(15):
        cur["a"] = {}
        cur = cur["a"]
    assert c.normalize_payload(root) == root


def test_canonicalization_error_is_a_value_error_and_a_ledger_error() -> None:
    e = mods().errors
    assert issubclass(e.CanonicalizationError, ValueError) and issubclass(e.CanonicalizationError, e.LedgerError)
