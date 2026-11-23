# ruff: noqa: E501
"""Strict canonical path: grammar boundaries, timestamps, budgets before work, error hygiene."""
from __future__ import annotations

import resource
import time
from datetime import UTC, datetime, timedelta, timezone

import pytest

from vulnscope.ledger import canonical as c
from vulnscope.ledger.errors import CanonicalizationError

OK_HASH = "ab" * 32


class _HostileStr(str):
    def __str__(self) -> str:
        raise RuntimeError("hostile __str__ called")

    __repr__ = __str__


# ------------------------------------------------------------------ grammar
@pytest.mark.parametrize(
    "cid",
    ["engagement:x", "intake:" + "a" * 200, "engagement:3f2c9a10-7b1e-4c55-9d0a-6e1b2c3d4e5f",
     "intake:a.b_c-D"],
)
def test_valid_chain_ids(cid: str) -> None:
    c.validate_chain_id(cid)


@pytest.mark.parametrize(
    "cid",
    ["engagement:x\n", "engagement:١", "intake:", "intake:" + "a" * 201, "engagement:a\x00b",
     "engagement:x ", "tenant:x", "", "Engagement:x", "engagement:a/b", "intake:\ud800"],
)
def test_invalid_chain_ids(cid: str) -> None:
    with pytest.raises(CanonicalizationError):
        c.validate_chain_id(cid)


def test_non_str_identifiers_raise_the_domain_error_not_typeerror() -> None:
    for fn in (c.validate_chain_id, c.validate_kind, c.validate_actor):
        for bad in (None, 5, b"x", _HostileStr("engagement:x")):
            with pytest.raises(CanonicalizationError):
                fn(bad)  # type: ignore[arg-type]


@pytest.mark.parametrize("good", ["a", "policy.decision", "x_1.y"])
def test_kind_ok(good: str) -> None:
    c.validate_kind(good)


@pytest.mark.parametrize("bad", ["", "A", "1a", "a b", "a-b", "a" * 65, "a\n"])
def test_kind_bad(bad: str) -> None:
    with pytest.raises(CanonicalizationError):
        c.validate_kind(bad)


@pytest.mark.parametrize("bad", ["", "a b", "a\n", "a" * 256, "é", "a/b"])
def test_actor_bad(bad: str) -> None:
    with pytest.raises(CanonicalizationError):
        c.validate_actor(bad)


def test_is_hash() -> None:
    assert c.is_hash(OK_HASH)
    for bad in (OK_HASH.upper(), OK_HASH[:63], OK_HASH + "\n", OK_HASH + "0", None, 5, "z" * 64):
        assert not c.is_hash(bad)


# ------------------------------------------------------------------ timestamps
def test_format_ts_always_six_digits_and_utc() -> None:
    assert c.format_ts(datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)) == "2026-01-02T03:04:05.000000Z"
    tz = timezone(timedelta(hours=5, minutes=30))
    assert c.format_ts(datetime(2026, 1, 2, 3, 4, 5, 7, tzinfo=tz)) == "2026-01-01T21:34:05.000007Z"
    assert c.format_ts(datetime(1, 1, 1, tzinfo=UTC)) == "0001-01-01T00:00:00.000000Z"


def test_format_ts_rejects_naive_and_out_of_range() -> None:
    with pytest.raises(CanonicalizationError):
        c.format_ts(datetime(2026, 1, 1))
    with pytest.raises(CanonicalizationError):
        c.format_ts(datetime(1, 1, 1, tzinfo=timezone(timedelta(hours=5))))  # overflows below year 1
    with pytest.raises(CanonicalizationError):
        c.format_ts("2026-01-01")  # type: ignore[arg-type]


def test_parse_ts_round_trip_and_strictness() -> None:
    ts = datetime(2026, 11, 19, 8, 30, 1, 123456, tzinfo=UTC)
    assert c.parse_ts(c.format_ts(ts)) == ts
    for bad in ("2026-11-19T08:30:00Z", "2026-11-19 08:30:00.000000Z", "2026-02-30T00:00:00.000000Z",
                "2026-11-19T24:00:00.000000Z", "2026-11-19T08:30:60.000000Z", "٢026-11-19T08:30:00.00000Z"):
        with pytest.raises(CanonicalizationError):
            c.parse_ts(bad)


# ------------------------------------------------------------------ strict canonical json
def test_tuple_becomes_list_and_keys_sort_by_code_point() -> None:
    assert c.canonical_json({"b": (1, 2), "a": None}) == b'{"a":null,"b":[1,2]}'


@pytest.mark.parametrize(
    "bad",
    [{"a": 1.0}, {"a": float("nan")}, {"a": b"x"}, {"a": bytearray(b"x")}, {"a": {1, 2}},
     {1: "a"}, {"a": 2**53}, {"a": -(2**53)}, {"a": "\ud800"}, {"\udfff": 1},
     {"a": _HostileStr("x")}, {_HostileStr("k"): 1}, {"a": datetime(2026, 1, 1, tzinfo=UTC)}, object()],
)
def test_rejected_values(bad: object) -> None:
    with pytest.raises(CanonicalizationError):
        c.canonical_json(bad)


def test_bool_is_not_confused_with_int_and_int_subclass_is_rejected() -> None:
    assert c.canonical_json({"a": True, "b": 1}) == b'{"a":true,"b":1}'

    class MyInt(int):
        pass

    with pytest.raises(CanonicalizationError):
        c.canonical_json({"a": MyInt(1)})


def test_error_messages_are_fixed_text() -> None:
    secret = "CANARY-" + "x" * 40
    for bad in ({"a": secret + "\ud800"}, {secret: 1.5}, {"a": {1: secret}}):
        with pytest.raises(CanonicalizationError) as info:
            c.canonical_json(bad)
        assert secret not in str(info.value) and secret not in repr(info.value)


def test_depth_boundary_for_payloads() -> None:
    def nest(n: int) -> dict[str, object]:
        root: dict[str, object] = {}
        cur = root
        for _ in range(n - 1):
            nxt: dict[str, object] = {}
            cur["a"] = nxt
            cur = nxt
        return root

    assert c.normalize_payload(nest(16)) == nest(16)
    with pytest.raises(CanonicalizationError):
        c.normalize_payload(nest(17))


def test_normalize_payload_returns_an_independent_copy() -> None:
    src = {"a": [1, {"b": 2}], "t": (1, 2)}
    out = c.normalize_payload(src)
    assert out == {"a": [1, {"b": 2}], "t": [1, 2]}
    out["a"][1]["b"] = 99  # type: ignore[index]
    assert src["a"][1]["b"] == 2  # type: ignore[index]


def test_normalize_payload_requires_a_dict_root() -> None:
    for bad in ([1], "x", None, 5):
        with pytest.raises(CanonicalizationError):
            c.normalize_payload(bad)  # type: ignore[arg-type]


def test_payload_size_cap_boundary() -> None:
    # 8 keys of 8 000 chars is 64 000 bytes plus structure: fits; 9 keys does not
    fits = {f"k{i}": "x" * 8_000 for i in range(8)}
    assert len(c.canonical_json(c.normalize_payload(fits))) <= c.MAX_PAYLOAD_BYTES
    with pytest.raises(CanonicalizationError):
        c.normalize_payload({f"k{i}": "x" * 8_000 for i in range(9)})


def _bounded(fn, *args) -> tuple[float, int]:
    before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    t0 = time.monotonic()
    with pytest.raises(CanonicalizationError):
        fn(*args)
    return time.monotonic() - t0, resource.getrusage(resource.RUSAGE_SELF).ru_maxrss - before


def test_budgets_trip_before_any_big_build() -> None:
    cyc: dict[str, object] = {}
    cyc["self"] = cyc
    deep: list[object] = []
    cur = deep
    for _ in range(100_000):
        nxt: list[object] = []
        cur.append(nxt)
        cur = nxt
    cases = {
        "100mb_string": {"a": "x" * 100_000_000},
        "1e6_keys": {f"k{i}": 0 for i in range(1_000_000)},
        "self_reference": cyc,
        "depth_1e5": {"d": deep},
        "hostile_str": {"a": _HostileStr("x")},
    }
    for name, value in cases.items():
        elapsed, grew_kb = _bounded(c.normalize_payload, value)
        assert elapsed < 1.0, name
        assert grew_kb < 100_000, name


# ------------------------------------------------------------------ hashing
def _kw(**over: object) -> dict[str, object]:
    base: dict[str, object] = {
        "schema_version": 1, "chain_id": "engagement:x", "seq": 0, "kind": "evidence",
        "actor": "system", "payload": {"a": 1}, "ts": datetime(2026, 1, 1, tzinfo=UTC),
        "prev_hash": c.genesis_hash("engagement:x"),
    }
    base.update(over)
    return base


def test_compute_record_hash_rejects_bad_inputs() -> None:
    for over in ({"schema_version": 2}, {"seq": -1}, {"seq": True}, {"prev_hash": OK_HASH.upper()},
                 {"kind": "Bad"}, {"actor": ""}, {"chain_id": "x"}, {"payload": {"f": 1.5}},
                 {"ts": datetime(2026, 1, 1)}):
        with pytest.raises(CanonicalizationError):
            c.compute_record_hash(**_kw(**over))  # type: ignore[arg-type]


def test_hash_input_is_ascii_hex_of_prev_plus_canonical_document() -> None:
    import hashlib

    kw = _kw()
    doc = c.canonical_json(c.entry_document(**kw))  # type: ignore[arg-type]
    expected = hashlib.sha256(str(kw["prev_hash"]).encode("ascii") + doc).hexdigest()
    assert c.compute_record_hash(**kw) == expected  # type: ignore[arg-type]


def test_checkpoint_message_domain_can_never_equal_a_record_hash_input() -> None:
    from vulnscope.ledger.checkpoint import MESSAGE_PREFIX

    assert not set(MESSAGE_PREFIX[:64]) <= set(b"0123456789abcdef")


def test_prepare_append_validates_before_anything_else() -> None:
    ts = datetime(2026, 1, 1, tzinfo=UTC)
    with pytest.raises(CanonicalizationError):
        c.prepare_append("bad", "evidence", "system", {}, ts)
    with pytest.raises(CanonicalizationError):
        c.prepare_append("engagement:x", "evidence", "system", {}, datetime(2026, 1, 1))
    p = c.prepare_append("engagement:x", "evidence", "system", {"a": (1,)}, ts)
    assert p.payload == {"a": [1]} and p.ts.tzinfo is not None
