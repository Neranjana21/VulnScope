# ruff: noqa: E501
"""Total sanitizer rules (design F1, fix round 2 R2.1 to R2.3). No database."""
from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

import pytest

from vulnscope.ledger import canonical as c

CANARY = "CANARY-SECRET-0123456789abcdef"
TS = datetime(2026, 11, 19, tzinfo=UTC)
BLOCKED = sorted(c.BLOCKED_KEYS)


def _san(obj: object) -> dict[str, object]:
    return c.sanitize_payload(obj)  # type: ignore[return-value]


def _records(out: dict[str, object]) -> list[dict[str, object]]:
    return out.get("sanitization", [])  # type: ignore[return-value]


# ------------------------------------------------------------------ R2.1 exact-key blocklist
def test_blocklist_is_exactly_the_fourteen_approved_keys() -> None:
    assert sorted(c.BLOCKED_KEYS) == sorted(
        ["authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "password",
         "passwd", "secret", "token", "api_key", "apikey", "private_key", "credential",
         "client_secret"]
    )


@pytest.mark.parametrize("key", BLOCKED)
@pytest.mark.parametrize("depth", [1, 3, "list"])
def test_each_blocked_key_is_redacted_case_insensitively_at_any_depth(key: str, depth: object) -> None:
    for k in (key, key.upper(), key.title()):
        if depth == 1:
            payload: dict[str, object] = {k: CANARY}
        elif depth == 3:
            payload = {"a": {"b": {k: CANARY, "keep": "v"}}}
        else:
            payload = {"items": [{"x": 1}, {k: CANARY}]}
        out = _san(payload)
        assert CANARY not in json.dumps(out)
        assert "[redacted]" in json.dumps(out)
        assert out["sanitized"] is True


def test_redacted_value_is_the_fixed_string_and_the_record_has_no_length_or_hash() -> None:
    out = _san({"password": CANARY})
    assert out["password"] == "[redacted]"
    assert _records(out) == [{"path": "$.password", "reason": "redacted"}]


def test_container_under_a_blocked_key_keeps_shape_and_redacts_string_leaves() -> None:
    out = _san({"cookie": {"a": "x", "n": 1, "deep": ["y", {"z": "w"}]}})
    assert out["cookie"] == {"a": "[redacted]", "n": 1, "deep": ["[redacted]", {"z": "[redacted]"}]}


def test_non_string_values_under_a_blocked_key_are_preserved() -> None:
    assert _san({"password": 123, "token": None, "secret": True}) == {
        "password": 123, "token": None, "secret": True}


@pytest.mark.parametrize(
    "payload",
    [
        {"authorization_basis": {"confirmed": True, "approver": "A", "statement_sha256": "ab" * 32}},
        {"secret_ref": "ref://engagements/e1/user_a"},
        {"token_count": 3},
        {"authorizations": "kept"},
        {"x_api_key": "kept-underscore-variant"},
        {"api-key": "kept"},
        {"Set-Cookie2": "kept"},
        {"passwords_policy": "kept"},
    ],
)
def test_substring_lookalikes_are_preserved_verbatim(payload: dict[str, object]) -> None:
    assert _san(payload) == payload


def test_header_lists_that_are_not_keyed_are_not_redacted_documented_limit() -> None:
    payload = {"headers": [["Authorization", "Bearer x"]]}
    assert _san(payload) == payload


# ------------------------------------------------------------------ R2.2 idempotence of strings
@pytest.mark.parametrize("n", [0, 1, 2047, 2048, 2049, 2048 - len("...[truncated:99999]"), 5000, 100_000])
def test_string_function_is_idempotent_at_the_boundaries(n: int) -> None:
    for s in ("a" * n, "\x00" * n, "é" * n, ("a" * n) + "...[truncated:7]"):
        once, _ = c._clean_str(s)
        twice, reason = c._clean_str(once)
        assert twice == once and reason is None
        assert len(once) <= c.STR_CAP


def test_truncation_cap_includes_the_suffix_and_records_length_and_hash() -> None:
    s = "A" * 3000
    out = _san({"t": s})
    assert len(out["t"]) == c.STR_CAP and out["t"].endswith("...[truncated:3000]")  # type: ignore[union-attr]
    (rec,) = _records(out)
    assert rec["reason"] == "truncated" and rec["orig_len"] == 3000
    assert rec["sha256"] == hashlib.sha256(s.encode()).hexdigest()


def test_hash_prefix_name_for_originals_above_one_mebibyte() -> None:
    s = "B" * (2 * 1024 * 1024)
    (rec,) = _records(_san({"t": s}))
    assert "sha256" not in rec
    assert rec["sha256_prefix_1mib"] == hashlib.sha256(s[: 1 << 20].encode()).hexdigest()


def test_short_escaped_string_records_length_only_no_hash() -> None:
    (rec,) = _records(_san({"t": "a\x00b"}))
    assert rec == {"path": "$.t", "reason": "escaped", "orig_len": 3}


def test_controls_and_surrogates_become_literal_text() -> None:
    out = _san({"t": "a\x00b\x7f\ud800c\n"})
    assert out["t"] == "a\\x00b\\x7f\\ud800c\\x0a"


def test_key_escaping_cap_collisions_and_non_str_keys() -> None:
    out = _san({"a\x00": 1, "a\\x00": 2, "k" * 300: 3, 1: 4, "ok": 5})
    keys = set(out) - {"sanitized", "sanitization"}
    assert "a\\x00" in keys and "a\\x00~1" in keys
    assert "k" * 128 in keys and "[key:3]" in keys and out["ok"] == 5
    assert len(keys) == 5


def test_non_finite_and_unsupported_leaves_are_markers() -> None:
    out = _san({"f": 1.5, "n": float("nan"), "b": b"x", "d": TS, "big": 2**64, "s": {1, 2}})
    assert out["f"] == out["n"] == "[float]"
    assert out["b"] == out["d"] == out["s"] == "[unsupported]"
    assert out["big"] == "[int_range]"


def test_caller_cannot_spoof_the_alteration_record() -> None:
    out = _san({"sanitized": False, "sanitization": ["fake"], "a": 1})
    assert out["sanitized"] is True and out["a"] == 1
    assert {r["reason"] for r in _records(out)} == {"dropped"}
    assert "fake" not in json.dumps(out)


# ------------------------------------------------------------------ provenance by type
def test_a_sanitized_payload_is_returned_unchanged_and_stored_as_is() -> None:
    s = c.sanitize_payload({"a": "x\x00y", "password": CANARY})
    assert c.sanitize_payload(s) is s
    assert c.prepare_payload(s) == dict(s)


def test_plain_copy_loses_provenance_and_reserved_keys_are_dropped_and_recorded() -> None:
    s = c.sanitize_payload({"a": "x\x00y"})
    plain = json.loads(json.dumps(s))
    again = c.sanitize_payload(plain)
    assert again is not s
    assert {k: v for k, v in again.items() if k not in ("sanitized", "sanitization")} == {
        k: v for k, v in s.items() if k not in ("sanitized", "sanitization")}
    assert any(r["reason"] == "dropped" for r in again["sanitization"])  # type: ignore[union-attr,index]


def test_a_mutated_sanitized_payload_fails_the_strict_check_and_is_resanitized() -> None:
    s = c.sanitize_payload({"a": 1})
    s["f"] = 1.5  # type: ignore[index]
    out = c.sanitize_payload(s)
    assert out["f"] == "[float]"


def test_clean_payload_is_unflagged_and_equal() -> None:
    clean = {"allowed": False, "rule_id": "X", "ips": ["192.0.2.1"], "n": 3}
    out = c.sanitize_payload(clean)
    assert out == clean and "sanitized" not in out


# ------------------------------------------------------------------ R2.3 totality
def test_non_dict_roots_have_a_defined_shape() -> None:
    out = _san([1, "a\x00"])
    assert out["sanitized"] is True and out["value"] == [1, "a\\x00"]
    assert {"path": "$", "reason": "marker"} in _records(out)
    assert _san(None)["value"] is None
    assert _san(5)["value"] == 5


def test_shared_subobject_is_emitted_twice_and_only_true_cycles_are_markers() -> None:
    shared = {"x": 1}
    out = _san({"a": shared, "b": shared, "l": [shared, shared]})
    assert out == {"a": {"x": 1}, "b": {"x": 1}, "l": [{"x": 1}, {"x": 1}]}
    cyc: dict[str, object] = {"k": 1}
    cyc["self"] = cyc
    out2 = _san({"c": cyc})
    assert out2["c"] == {"k": 1, "self": "[cycle]"}


def test_depth_is_capped_with_a_marker() -> None:
    root: dict[str, object] = {}
    cur = root
    for _ in range(20):
        nxt: dict[str, object] = {}
        cur["a"] = nxt
        cur = nxt
    assert "[depth]" in json.dumps(_san(root))


def test_node_and_item_budgets() -> None:
    out = _san({"l": list(range(500_000))})
    assert len(out["l"]) == c.SAN_MAX_ITEMS  # type: ignore[arg-type]
    assert any(r["reason"] == "dropped" and r["count"] == 500_000 - 64 for r in _records(out))
    out2 = _san({f"k{i}": i for i in range(200_000)})
    assert len([k for k in out2 if k.startswith("k")]) <= c.TOP_KEYS_MAX


def test_exact_type_tests_never_call_user_methods() -> None:
    class Boom:
        def __str__(self) -> str:
            raise RuntimeError("called")

        __repr__ = __str__
        __iter__ = __str__  # type: ignore[assignment]
        __eq__ = __str__  # type: ignore[assignment]
        __hash__ = None  # type: ignore[assignment]

    class BoomStr(str):
        def __str__(self) -> str:
            raise RuntimeError("called")

    class BoomMap(dict):  # type: ignore[type-arg]
        def items(self):  # type: ignore[no-untyped-def]
            raise RuntimeError("called")

    out = _san({"a": Boom(), "b": [BoomStr("x")], "c": BoomMap(x=1)})
    assert out["a"] == "[unsupported]" and out["b"] == ["[unsupported]"] and out["c"] == "[unsupported]"


def test_dict_mutated_by_another_thread_mid_snapshot_becomes_a_marker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CPython raises RuntimeError when a dict changes size during iteration; the container
    becomes the marker and the rest of the payload continues (R2.3 (v))."""
    real = c.islice
    calls = {"n": 0}

    def flaky(iterable: object, stop: int) -> object:
        calls["n"] += 1
        if calls["n"] == 2:  # the nested dict, not the top level
            raise RuntimeError("dictionary changed size during iteration")
        return real(iterable, stop)  # type: ignore[call-overload]

    monkeypatch.setattr(c, "islice", flaky)
    out = c.sanitize_payload({"a": {"x": 1}, "rule_id": "R", "n": [1]})
    assert out["a"] == "[unstable]" and out["rule_id"] == "R" and out["n"] == [1]


def test_base_exceptions_pass_through(monkeypatch: pytest.MonkeyPatch) -> None:
    def interrupt(*_: object, **__: object) -> object:
        raise KeyboardInterrupt

    monkeypatch.setattr(c, "_sanitize", interrupt)
    with pytest.raises(KeyboardInterrupt):
        c.sanitize_payload({"a": 1})


@pytest.mark.parametrize("exc", [RecursionError, MemoryError, ValueError])
def test_fault_injection_falls_back_but_keeps_scalars(
    monkeypatch: pytest.MonkeyPatch, exc: type[Exception]
) -> None:
    def broken(*_: object, **__: object) -> object:
        raise exc("boom")

    monkeypatch.setattr(c, "_sanitize", broken)
    out = c.sanitize_payload({"allowed": False, "rule_id": "OUT_OF_SCOPE", "x": [1], "f": 1.5, "n": 7})
    assert out["allowed"] is False and out["rule_id"] == "OUT_OF_SCOPE" and out["n"] == 7
    assert "x" not in out and "f" not in out
    assert out["sanitized"] is True and out["sanitization"] == [{"reason": "fallback"}]
    c.normalize_payload(out)


def test_fallback_on_a_non_dict_is_the_plain_marker() -> None:
    assert dict(c._fallback([1, 2])) == {"sanitized": True, "sanitization": [{"reason": "fallback"}]}


# ------------------------------------------------------------------ R2.2 budgets (R1-2 starvation)
def test_long_strings_placed_first_cannot_starve_later_scalar_keys() -> None:
    big = "\U0001F600" * 2048  # four-byte characters
    payload: dict[str, object] = {f"s{i}": big for i in range(100)}
    payload["rule_id"] = "OUT_OF_SCOPE"
    payload["allowed"] = False
    out = c.sanitize_payload(payload)
    assert out["rule_id"] == "OUT_OF_SCOPE" and out["allowed"] is False
    assert out["sanitized"] is True and out["sanitization"] != [{"reason": "fallback"}]
    assert len(c.canonical_json(c.normalize_payload(out))) <= 32 * 1024 + 4 * 1024


def test_one_big_list_cannot_starve_later_keys_and_redirect_chains_fit() -> None:
    hops = [{"url": "http://h%d.lab.test/" % i + "p" * 2000, "status": 302} for i in range(64)]
    out = c.sanitize_payload({"redirects": hops, "rule_id": "R", "allowed": True})
    assert out["rule_id"] == "R" and out["allowed"] is True
    assert len(c.canonical_json(c.normalize_payload(out))) <= 32 * 1024 + 4 * 1024


def test_in_contract_policy_decision_payload_is_never_the_fallback() -> None:
    payload = {
        "allowed": False, "rule_id": "ALWAYS_DENY_LINK_LOCAL", "target": "169.254.169.254",
        "resolved_ips": ["169.254.169.254"], "reason": "metadata address",
        "engagement_id": "e1", "request_id": "r-1",
    }
    out = c.sanitize_payload(payload)
    assert out == payload


def test_output_is_always_valid_for_the_strict_path() -> None:
    for payload in ({"t": "A" * 100_000_000}, {"t": "\x00" * 50_000}, {"k": {"x" * 400: "y"}}):
        out = c.sanitize_payload(payload)
        c.normalize_payload(out)
