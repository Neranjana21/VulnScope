# ruff: noqa: E501
"""Stress (R1): hostile target data must never prevent a decision from being recorded (rule 8) and
must never leak a secret into storage (rules 6 and 9). Design: docs/gates/task-b-design.md F1
(total sanitizer, enforced inside append()), F4, R-3; owner decision B-R1-3 (2026-11-19): the
redaction blocklist is an EXACT-key, case-insensitive match replacing STRING values with the fixed
string "[redacted]"; keys such as ``secret_ref``, ``token_count`` and ``authorization_basis`` are NOT
redacted. Slice-gate follow-up (not testable here): the same payloads through Task A's
``decide_and_record`` on a DENY.

Assertions on huge or cyclic inputs are computed as booleans BEFORE asserting, so a failure never
makes pytest repr a 100 MB string or a 10^5-deep structure.
"""
from __future__ import annotations

import json
import time
import uuid
from datetime import UTC, datetime

import pytest
from ledger_r1_support import BASE_TS, mods, run

CANARY = "CANARY-SECRET-" + uuid.uuid4().hex
CHAIN = "intake:dddddddd-dddd-4ddd-8ddd-dddddddddddd"
MAX_BYTES = 65_536

BLOCKLIST = ["authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "password",
             "passwd", "secret", "token", "api_key", "apikey", "private_key", "credential", "client_secret"]


class _Boom(str):
    def __str__(self) -> str:  # a hostile str subclass: no user-defined method may be called
        raise RuntimeError("hostile __str__ called")

    __repr__ = __str__


class _BoomObj:
    def __str__(self) -> str:
        raise RuntimeError("hostile __str__ called")

    __repr__ = __str__

    def __iter__(self):
        raise RuntimeError("hostile __iter__ called")

    def __eq__(self, other):
        raise RuntimeError("hostile __eq__ called")

    __hash__ = None  # type: ignore[assignment]


class _BoomInt(int):
    def __repr__(self) -> str:
        raise RuntimeError("hostile __repr__ called")


class _BoomMap(dict):
    def items(self):
        raise RuntimeError("hostile items called")

    def __iter__(self):
        raise RuntimeError("hostile __iter__ called")


def _cyclic_dict():
    d: dict = {"k": 1}
    d["self"] = d
    return d


def _cyclic_list():
    x: list = [1]
    x.append(x)
    return {"c": x}


def _deep(n=100_000):
    root: list = []
    cur = root
    for _ in range(n):
        nxt: list = []
        cur.append(nxt)
        cur = nxt
    return {"deep": root}


NOT_FLAGGED = {"bidi_and_emoji"}
HOSTILE = {
    "lone_surrogate_target": lambda: {"target": "\ud800host\udfff.lab.test", "ok": 1},
    "lone_surrogate_key": lambda: {"\ud800": 1},
    "nul_and_controls": lambda: {"target": "a\x00b\x01c\x1fd\x7fe f"},
    "bidi_and_emoji": lambda: {"target": "‮⁦evil\U0001F600"},
    "mb_string_1": lambda: {"target": "A" * 1_000_000 + CANARY},
    "mb_string_100": lambda: {"target": "B" * 100_000_000},
    "floats": lambda: {"a": 1.5, "b": float("nan"), "c": float("inf"), "d": -0.0, "e": 2.0},
    "bytes_datetime": lambda: {"a": b"\xff\xfe", "b": datetime(2026, 1, 1, tzinfo=UTC), "c": bytearray(b"x")},
    "huge_ints": lambda: {"a": 2**64, "b": -(2**200), "c": 2**53},
    "non_str_keys": lambda: {1: "a", (1, 2): "b", b"k": "c", None: "d", 2.5: "e"},
    "colliding_keys_after_escape": lambda: {"a\x00": 1, "a\x01": 2, "a\\x00": 3},
    "hostile_str_subclass": lambda: {"a": _Boom("x"), "b": [_Boom("y")]},
    "hostile_object": lambda: {"a": _BoomObj(), "b": [_BoomObj()]},
    "hostile_int_subclass": lambda: {"a": _BoomInt(5)},
    "hostile_mapping_subclass": lambda: {"a": _BoomMap(x=1)},
    "cyclic_dict": _cyclic_dict,
    "cyclic_list": _cyclic_list,
    "deep_100k": _deep,
    "many_keys_200k": lambda: {f"k{i}": i for i in range(200_000)},
    "many_items_list": lambda: {"l": list(range(500_000))},
    "spoofed_sanitized_flags": lambda: {"sanitized": False, "sanitization": ["fake"], "a": 1},
    "set_tuple_frozenset": lambda: {"a": {1, 2}, "b": (1, 2), "c": frozenset({3})},
}


def _stored_blob(entries) -> str:
    return json.dumps([e.payload for e in entries], ensure_ascii=True, sort_keys=True)


@pytest.mark.parametrize("name", sorted(HOSTILE))
async def test_hostile_payload_is_recorded_sanitized_verified_and_bounded(name: str) -> None:
    m = mods()
    payload = HOSTILE[name]()
    b = m.memory_backend.InMemoryChainBackend()
    t0 = time.monotonic()
    try:
        entry = await b.append(CHAIN, "policy.decision", "system", payload, BASE_TS)
        raised = None
    except BaseException as exc:  # noqa: BLE001
        raised = type(exc).__name__
    elapsed = time.monotonic() - t0
    assert raised is None, f"append raised {raised}: a DENY could not be recorded (rule 8)"
    rows = [e async for e in b.read(CHAIN)]
    res = await m.verify.verify(CHAIN, b)
    size = len(m.canonical.canonical_json(dict(entry.payload)))
    checks = {
        "exactly_one_entry": len(rows) == 1 and rows[0].kind == "policy.decision",
        "verify_ok": (res.result, res.records) == ("ok", 1),
        # bidi/emoji text is unchanged by the F1 rules (only C0, DEL, surrogates are escaped), so the
        # flag is not asserted for it either way
        "sanitized_flag": name in NOT_FLAGGED or entry.payload.get("sanitized") is True,
        "read_equals_append": dict(rows[0].payload) == dict(entry.payload),
        "size_bounded": size <= MAX_BYTES,
        "fast": elapsed < 15.0,
        # mb_string_1 plants the canary at the END of a 1 MB string: F1 truncates, so it is dropped
        "canary_absent": CANARY not in _stored_blob(rows),
    }
    failed = sorted(k for k, ok in checks.items() if not ok)
    assert not failed, f"{name}: failed checks {failed}"


async def test_spoofed_sanitized_flags_cannot_forge_the_alteration_record() -> None:
    m = mods()
    b = m.memory_backend.InMemoryChainBackend()
    e = await b.append(CHAIN, "policy.decision", "system", {"sanitized": False, "sanitization": ["fake"], "a": 1}, BASE_TS)
    assert e.payload["sanitized"] is True
    rec = e.payload["sanitization"]
    assert isinstance(rec, list) and all(isinstance(x, dict) for x in rec) and rec
    assert "fake" not in json.dumps(dict(e.payload))
    assert e.payload["a"] == 1


async def test_clean_payload_is_stored_unchanged_without_flags() -> None:
    m = mods()
    b = m.memory_backend.InMemoryChainBackend()
    clean = {"allowed": False, "rule_id": "OUT_OF_SCOPE", "target": "a.lab.test", "ips": ["192.0.2.1"], "n": 3}
    e = await b.append(CHAIN, "policy.decision", "system", clean, BASE_TS)
    assert dict(e.payload) == clean and "sanitized" not in e.payload


def test_100mb_string_is_bounded_in_time_and_memory() -> None:
    import resource

    m = mods()
    big = "C" * 100_000_000
    before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    t0 = time.monotonic()
    out = m.canonical.sanitize_payload({"t": big, "k": CANARY})
    elapsed = time.monotonic() - t0
    grew_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss - before
    n = len(m.canonical.canonical_json(m.canonical.normalize_payload(out)))
    assert elapsed < 5.0 and n <= MAX_BYTES and grew_kb < 150_000


# ------------------------------------------------------------------ owner decision B-R1-3
def _variants(key: str) -> list[str]:
    alt = "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(key))
    return sorted({key, key.upper(), key.title(), alt})


@pytest.mark.parametrize("key", BLOCKLIST)
async def test_blocklisted_key_any_case_any_depth_string_value_is_redacted(key: str) -> None:
    m = mods()
    secret = "Bearer " + CANARY if key in ("authorization", "proxy-authorization") else CANARY
    for k in _variants(key):
        payload = {
            k: secret,
            "request": {"headers": {k: secret, "accept": "text/html"}, "list": [{"x": 1, k: secret}]},
            "deeper": {"a": {"b": {"c": {k: secret}}}},
        }
        b = m.memory_backend.InMemoryChainBackend()
        e = await b.append(CHAIN, "policy.decision", "system", payload, BASE_TS)
        p = e.payload
        assert p[k] == "[redacted]"
        assert p["request"]["headers"][k] == "[redacted]"  # type: ignore[index]
        assert p["request"]["headers"]["accept"] == "text/html"  # type: ignore[index]
        assert p["request"]["list"][0][k] == "[redacted]" and p["request"]["list"][0]["x"] == 1  # type: ignore[index]
        assert p["deeper"]["a"]["b"]["c"][k] == "[redacted]"  # type: ignore[index]
        stored = _stored_blob([e for e in [x async for x in b.read(CHAIN)]])
        assert CANARY not in stored, f"canary stored for key variant {k!r}"


async def test_real_authorization_header_string_is_redacted_and_canary_absent_from_storage() -> None:
    m = mods()
    b = m.memory_backend.InMemoryChainBackend()
    hdr = "Bearer " + CANARY
    for k in ("Authorization", "AUTHORIZATION", "authorization", "aUtHoRiZaTiOn", "Proxy-Authorization"):
        await b.append(CHAIN, "policy.decision", "system",
                       {"observed": {"response": {"headers": {k: hdr, "Server": "lab"}}}}, BASE_TS)
    rows = [e async for e in b.read(CHAIN)]
    assert len(rows) == 5
    assert all(r.payload["observed"]["response"]["headers"][k] == "[redacted]" for r, k in zip(  # type: ignore[index]
        rows, ("Authorization", "AUTHORIZATION", "authorization", "aUtHoRiZaTiOn", "Proxy-Authorization"), strict=True))
    assert CANARY not in _stored_blob(rows) and "Bearer" not in _stored_blob(rows)
    assert (await m.verify.verify(CHAIN, b)).result == "ok"


async def test_non_matching_keys_are_not_redacted_authorization_basis_preserved() -> None:
    m = mods()
    b = m.memory_backend.InMemoryChainBackend()
    payload = {
        "secret_ref": "vault://lab/secrets/7", "token_count": "17",
        "authorization_basis": {"confirmed": True, "statement": "approved in writing by the lab owner", "approver": "alice"},
        "nested": {"secret_ref": "vault://lab/secrets/8", "authorization_basis": "engagement 42"},
    }
    e = await b.append(CHAIN, "engagement.created", "user:alice", payload, BASE_TS)
    assert dict(e.payload) == payload and "sanitized" not in e.payload
    assert "[redacted]" not in json.dumps(dict(e.payload))


async def test_redaction_is_exact_key_not_substring() -> None:
    m = mods()
    b = m.memory_backend.InMemoryChainBackend()
    payload = {"authorization_basis": "kept", "secret_ref": "kept", "token_count": "kept", "passwords_policy": "kept"}
    e = await b.append(CHAIN, "policy.decision", "system", payload, BASE_TS)
    assert all(v == "kept" for v in e.payload.values())


async def test_redacted_value_is_the_fixed_string_not_a_hash_or_prefix() -> None:
    m = mods()
    out = m.canonical.sanitize_payload({"password": CANARY, "Token": CANARY + "2"})
    assert out["password"] == "[redacted]" and out["Token"] == "[redacted]"
    assert CANARY not in json.dumps(out)


# ------------------------------------------------------------------ totality (hypothesis)
def test_sanitize_is_total_strict_valid_bounded_and_idempotent_property() -> None:
    from hypothesis import HealthCheck, given, settings
    from hypothesis import strategies as st

    m = mods()
    codepoint_text = st.lists(st.integers(0, 0x10FFFF), max_size=40).map(lambda cps: "".join(map(chr, cps)))
    leaf = st.one_of(st.none(), st.booleans(), st.integers(-(2**70), 2**70), st.floats(), codepoint_text,
                     st.binary(max_size=8), st.datetimes(), st.just(object()), st.builds(_BoomObj), codepoint_text.map(_Boom))
    key = st.one_of(codepoint_text, st.integers(), st.binary(max_size=3), st.just(None))
    tree = st.recursive(leaf, lambda c: st.one_of(st.lists(c, max_size=5), st.tuples(c, c),
                                                   st.dictionaries(key, c, max_size=5)), max_leaves=40)

    @given(tree=tree, with_secret=st.booleans())
    @settings(max_examples=250, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large])
    def prop(tree, with_secret: bool) -> None:
        payload = {"t": tree}
        if with_secret:
            payload["Authorization"] = "Bearer " + CANARY
        out = m.canonical.sanitize_payload(payload)
        assert isinstance(out, dict)
        n = len(m.canonical.canonical_json(m.canonical.normalize_payload(out)))
        assert n <= MAX_BYTES
        assert m.canonical.sanitize_payload(out) == out
        assert CANARY not in json.dumps(out, ensure_ascii=True)
        b = m.memory_backend.InMemoryChainBackend()
        run(b.append(CHAIN, "policy.decision", "system", payload, BASE_TS))
        assert run(m.verify.verify(CHAIN, b)).result == "ok"

    prop()


@pytest.mark.parametrize("obj", [None, 5, "x", [1, 2], (1,), object(), _BoomObj(), _BoomMap(a=1), b"b", 1.5, float("nan")])
def test_sanitize_is_total_even_for_non_dict_top_level(obj: object) -> None:
    out = mods().canonical.sanitize_payload(obj)
    assert isinstance(out, dict)


# ------------------------------------------------------------------ Postgres variant
PG_CASES = ["lone_surrogate_target", "nul_and_controls", "mb_string_1", "floats", "bytes_datetime", "non_str_keys",
            "cyclic_dict", "deep_100k", "spoofed_sanitized_flags", "hostile_str_subclass"]


@pytest.mark.integration
def test_postgres_hostile_payloads_recorded_once_each_and_canary_absent(request: pytest.FixtureRequest) -> None:
    from ledger_r1_support import pg_admin_fetch, pg_backend, pg_scratch

    db = pg_scratch(request)
    m = mods()
    cid = f"intake:{uuid.uuid4()}"

    async def go():
        engine, backend = await pg_backend(db)
        try:
            for name in PG_CASES:
                p = HOSTILE[name]()
                if isinstance(p, dict):
                    p = {**p, "Authorization": "Bearer " + CANARY} if name != "non_str_keys" else p
                await backend.append(cid, "policy.decision", "system", p, BASE_TS)
            await backend.append(cid, "policy.decision", "system", {"password": CANARY, "cookie": CANARY}, BASE_TS)
            return await m.verify.verify(cid, backend), [e async for e in backend.read(cid)]
        finally:
            await engine.dispose()

    res, rows = run(go())
    assert (res.result, res.records) == ("ok", len(PG_CASES) + 1)
    assert [e.seq for e in rows] == list(range(len(PG_CASES) + 1)) and all(e.kind == "policy.decision" for e in rows)
    stored = pg_admin_fetch(db, "SELECT payload::text AS p FROM ledger_entries WHERE chain_id = $1 ORDER BY seq", cid)
    assert len(stored) == len(PG_CASES) + 1
    assert not any(CANARY in r["p"] for r in stored)
    assert all(len(r["p"].encode("utf-8")) <= MAX_BYTES * 2 for r in stored)
