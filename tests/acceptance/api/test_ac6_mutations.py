"""AC6 (design 12.4 / PD-18): every invalid engagement-creation case in io-contracts yields the right
reason code AND one ``engagement.rejected`` entry on ``intake:<org>``; transport-level failures
yield INVALID_REQUEST and NO ledger entry. Fixed precedence is pinned by rows 14 and the
precedence cases."""
from __future__ import annotations

import copy
import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from acc_support import FMT, World, assert_problem, engagement_payload

# Literal list (the meta-test reads it with ast); test_ac6_declared_codes_match_the_cases keeps it
# honest against the parametrized table.
pytestmark = [
    pytest.mark.acceptance,
    pytest.mark.covers_code(
        "AUTH_NOT_CONFIRMED", "SCOPE_EMPTY", "TARGET_DENIED", "TARGET_NOT_IN_SCOPE",
        "RATE_ABOVE_CEILING", "WINDOW_MISSING", "WINDOW_EXPIRED", "WINDOW_NAIVE_DATETIME",
        "WINDOW_TOO_LONG", "SECRET_INLINE", "UNKNOWN_FIELD"),
]
AC6_DECLARED = {
    "AUTH_NOT_CONFIRMED", "SCOPE_EMPTY", "TARGET_DENIED", "TARGET_NOT_IN_SCOPE",
    "RATE_ABOVE_CEILING", "WINDOW_MISSING", "WINDOW_EXPIRED", "WINDOW_NAIVE_DATETIME",
    "WINDOW_TOO_LONG", "SECRET_INLINE", "UNKNOWN_FIELD"}

Mut = Callable[[dict[str, Any]], None]
BAD_SECRET_REF = "ref://A/b"  # does not match the secret_ref pattern: SECRET_INLINE


def _confirm_false(p: dict[str, Any]) -> None:
    p["authorization"]["confirmed"] = False


def _allow_empty(p: dict[str, Any]) -> None:
    p["scope"]["allow"] = []


def _not_in_allow(p: dict[str, Any]) -> None:
    p["targets"]["domains"] = ["other.lab.test"]


def _deny_target(p: dict[str, Any]) -> None:
    p["scope"]["deny"] = ["target.lab.test"]


def _meta_allowed(p: dict[str, Any]) -> None:
    p["targets"]["domains"] = ["169.254.169.254"]
    p["scope"]["allow"] = ["169.254.169.254"]


def _meta_not_allowed(p: dict[str, Any]) -> None:
    p["targets"]["domains"] = ["169.254.169.254"]  # allow still only target.lab.test


def _rate_over(p: dict[str, Any]) -> None:
    p["scope"]["rate_limit_rps"] = 10.0001


def _no_window(p: dict[str, Any]) -> None:
    del p["scope"]["window"]


def _no_not_after(p: dict[str, Any]) -> None:
    del p["scope"]["window"]["not_after"]


def _expired(p: dict[str, Any]) -> None:
    p["scope"]["window"]["not_after"] = (datetime.now(UTC) - timedelta(seconds=1)).strftime(FMT)


def _naive(p: dict[str, Any]) -> None:
    p["scope"]["window"]["not_before"] = "2026-01-01T00:00:00"


def _too_long(p: dict[str, Any]) -> None:
    nb = datetime.now(UTC) - timedelta(minutes=1)
    p["scope"]["window"]["not_before"] = nb.strftime(FMT)
    p["scope"]["window"]["not_after"] = (nb + timedelta(days=90, seconds=1)).strftime(FMT)


def _inline_secret(p: dict[str, Any]) -> None:
    p["identities"] = [{"label": "a", "role": "r",
                        "auth": {"type": "bearer", "secret_ref": BAD_SECRET_REF}}]


def _unknown_root(p: dict[str, Any]) -> None:
    p["foo_canary"] = 1


def _unknown_nested(p: dict[str, Any]) -> None:
    p["scope"]["foo_canary"] = 1


def _two(p: dict[str, Any]) -> None:
    _confirm_false(p)
    _allow_empty(p)


def _case(id_: str, mut: Mut, code: str, codes: list[str] | None = None,
          canaries: tuple[str, ...] = ()) -> Any:
    return pytest.param(mut, code, codes, canaries, id=id_)


CASES = [
    _case("01-auth-not-confirmed", _confirm_false, "AUTH_NOT_CONFIRMED"),
    _case("02-scope-empty", _allow_empty, "SCOPE_EMPTY"),
    _case("03-target-not-in-scope", _not_in_allow, "TARGET_NOT_IN_SCOPE", None,
          ("other.lab.test",)),
    _case("04-target-denied-excluded", _deny_target, "TARGET_DENIED"),
    _case("05a-metadata-in-allow", _meta_allowed, "TARGET_DENIED", None, ("169.254.169.254",)),
    _case("05b-metadata-not-in-allow", _meta_not_allowed, "TARGET_DENIED", None,
          ("169.254.169.254",)),
    _case("06-rate-above-ceiling", _rate_over, "RATE_ABOVE_CEILING"),
    _case("07a-window-missing", _no_window, "WINDOW_MISSING"),
    _case("07b-not-after-missing", _no_not_after, "WINDOW_MISSING"),
    _case("08-window-expired", _expired, "WINDOW_EXPIRED"),
    _case("09-window-naive", _naive, "WINDOW_NAIVE_DATETIME", None, ("2026-01-01T00:00:00",)),
    _case("10-window-too-long", _too_long, "WINDOW_TOO_LONG"),
    _case("11-secret-inline", _inline_secret, "SECRET_INLINE", None, (BAD_SECRET_REF,)),
    _case("12a-unknown-field-root", _unknown_root, "UNKNOWN_FIELD", None, ("foo_canary",)),
    _case("12b-unknown-field-nested", _unknown_nested, "UNKNOWN_FIELD", None, ("foo_canary",)),
    _case("14-two-violations-fixed-precedence", _two, "AUTH_NOT_CONFIRMED",
          ["AUTH_NOT_CONFIRMED", "SCOPE_EMPTY"]),
]


def test_ac6_declared_codes_match_the_cases() -> None:
    assert {c.values[1] for c in CASES} == AC6_DECLARED


def _assert_rejection(world: World, actor: Any, resp: Any, code: str,
                      codes: list[str] | None, canaries: tuple[str, ...], p: dict[str, Any],
                      intake_before: int) -> None:
    body = assert_problem(resp, 422, code)
    rows = world.ledger_rows(actor.intake)
    assert len(rows) == intake_before + 1  # exactly one new intake entry
    new = rows[-1]
    assert isinstance(body["ledger_seq"], int) and body["ledger_seq"] == new["seq"]
    assert new["kind"] == "engagement.rejected"
    assert new["actor"] == f"user:{actor.key_id}"
    assert new["payload"]["primary"] == code and code in new["payload"]["codes"]
    if codes is not None:
        assert new["payload"]["codes"] == codes
    assert world.engagements_of(actor.org_id) == 0
    assert world.engagement_entries_by(actor) == 0  # this key wrote on no engagement chain
    blob = json.dumps(new["payload"])
    for canary in (p["name"], p["authorization"]["statement"], p["authorization"]["approver"],
                   *canaries):
        assert canary not in blob  # nothing from the body reaches the ledger payload


@pytest.mark.parametrize("mut,code,codes,canaries", CASES)
def test_ac6_rejection_matrix(world: World, mut: Mut, code: str, codes: list[str] | None,
                              canaries: tuple[str, ...]) -> None:
    actor = world.org("admin")  # a fresh org: its intake chain starts empty
    p = engagement_payload()
    mut(p)
    intake_before = len(world.ledger_rows(actor.intake))
    resp = world.create(actor, p)
    _assert_rejection(world, actor, resp, code, codes, canaries, p, intake_before)


@pytest.mark.covers_code("PROFILE_NOT_ENABLED")
def test_ac6_13_profile_not_enabled(world_nolab: World) -> None:
    w = world_nolab
    actor = w.org("admin")
    p = engagement_payload()
    resp = w.create(actor, p)
    _assert_rejection(w, actor, resp, "PROFILE_NOT_ENABLED", None, (), p, 0)


def test_ac6_controls_exact_boundaries_are_accepted(world: World) -> None:
    actor = world.org("admin")
    ok = engagement_payload()
    ok["scope"]["rate_limit_rps"] = 10
    assert world.create(actor, ok).status_code == 201  # ceiling itself is fine
    ok2 = engagement_payload()
    nb = datetime.now(UTC) - timedelta(minutes=1)
    ok2["scope"]["window"] = {"not_before": nb.strftime(FMT),
                              "not_after": (nb + timedelta(days=90)).strftime(FMT)}
    assert world.create(actor, ok2).status_code == 201  # exactly 90 d is fine


def _deny_other_not_allowed(p: dict[str, Any]) -> None:
    """Deny matches a target that is also outside allow: deny wins over coverage."""
    p["targets"]["domains"] = ["other.lab.test"]
    p["scope"]["deny"] = ["other.lab.test"]


PRECEDENCE = [
    # (mutations applied together, expected primary code): schema phase first, then semantic.
    ([_unknown_root, _naive], "UNKNOWN_FIELD"),
    ([_naive, _no_not_after], "WINDOW_NAIVE_DATETIME"),
    ([_confirm_false, _rate_over, _expired], "AUTH_NOT_CONFIRMED"),
    ([_allow_empty, _rate_over], "SCOPE_EMPTY"),
    ([_rate_over, _expired], "RATE_ABOVE_CEILING"),
    ([_deny_other_not_allowed], "TARGET_DENIED"),
]


@pytest.mark.parametrize("muts,primary", PRECEDENCE,
                         ids=[f"{i}-{pr}" for i, (_, pr) in enumerate(PRECEDENCE)])
def test_ac6_fixed_precedence(world: World, muts: list[Mut], primary: str) -> None:
    actor = world.org("admin")
    p = engagement_payload()
    for m in muts:
        m(p)
    body = assert_problem(world.create(actor, p), 422, primary)
    assert isinstance(body["ledger_seq"], int)
    assert world.ledger_rows(actor.intake)[-1]["payload"]["primary"] == primary


def _big() -> bytes:
    return json.dumps({"pad": "a" * 300_000}).encode()


def _chunks(data: bytes) -> Any:
    for i in range(0, len(data), 8192):
        yield data[i:i + 8192]


def _not_ledgered_cases() -> list[Any]:
    def tweak(fn: Mut) -> Callable[[], dict[str, Any]]:
        def build() -> dict[str, Any]:
            p = engagement_payload()
            fn(p)
            return p

        return build

    def set_rps0(p: dict[str, Any]) -> None:
        p["scope"]["rate_limit_rps"] = 0

    def set_name_int(p: dict[str, Any]) -> None:
        p["name"] = 5

    def set_name_long(p: dict[str, Any]) -> None:
        p["name"] = "n" * 256

    def set_name_nul(p: dict[str, Any]) -> None:
        p["name"] = "bad\u0000name"

    raw_nan = json.dumps(engagement_payload()).replace('"rate_limit_rps": 5',
                                                       '"rate_limit_rps": NaN').encode()
    full = json.dumps(engagement_payload()).encode()
    return [
        pytest.param({"body": tweak(set_rps0)}, 422, id="rate-zero"),
        pytest.param({"raw": raw_nan}, 400, id="nan-literal"),
        pytest.param({"body": tweak(set_name_int)}, 422, id="name-wrong-type"),
        pytest.param({"body": tweak(set_name_long)}, 422, id="name-256-chars"),
        pytest.param({"body": tweak(set_name_nul)}, 422, id="name-nul"),
        pytest.param({"raw": full, "headers": {"Content-Type": "text/plain"}}, 415,
                     id="content-type-text-plain"),
        pytest.param({"raw": _big()}, 413, id="body-300kb-declared-length"),
        pytest.param({"raw": _chunks(_big())}, 413, id="body-300kb-chunked"),
        pytest.param({"raw": b""}, 400, id="empty-body"),
        pytest.param({"raw": full[: len(full) // 2]}, 400, id="truncated-json"),
        pytest.param({"body": lambda: engagement_payload(), "key": "k" * 256}, 422,
                     id="idempotency-key-256-chars"),
        pytest.param({"body": lambda: engagement_payload(),
                      "headers": {"Idempotency-Key": "a"}, "dup_key": True}, 422,
                     id="two-idempotency-key-headers"),
    ]


@pytest.mark.covers_code("INVALID_REQUEST")
@pytest.mark.parametrize("spec,status", _not_ledgered_cases())
def test_ac6_transport_failures_are_invalid_request_and_never_ledgered(
        world: World, spec: dict[str, Any], status: int) -> None:
    actor = world.org("admin")
    before = len(world.ledger_rows(actor.intake))
    if spec.get("dup_key"):
        resp = world.client.post(
            "/v1/engagements", content=json.dumps(engagement_payload()),
            headers=[("Authorization", f"Bearer {actor.token}"),  # type: ignore[arg-type]
                     ("Content-Type", "application/json"),
                     ("Idempotency-Key", "a"), ("Idempotency-Key", "b")])
    elif "raw" in spec:
        resp = world.post("/v1/engagements", actor, raw=spec["raw"],
                          headers=spec.get("headers"))
    else:
        resp = world.post("/v1/engagements", actor, spec["body"](), key=spec.get("key"),
                          headers=spec.get("headers"))
    body = assert_problem(resp, status, "INVALID_REQUEST")
    assert "ledger_seq" not in body
    assert len(world.ledger_rows(actor.intake)) == before  # no engagement.rejected
    assert world.engagements_of(actor.org_id) == 0
    assert world.engagement_entries_by(actor) == 0


def test_ac6_unauthenticated_413_precedes_nothing_else(world: World) -> None:
    """Pre-auth: a chunked oversize body without a key is a 401 (the body is never read)."""
    resp = world.post("/v1/engagements", None, raw=_chunks(_big()))
    assert_problem(resp, 401, "UNAUTHENTICATED")


def test_ac6_rejection_body_is_deterministic_per_code(world: World) -> None:
    """The 422 body for one mutation is identical across two orgs except request_id/instance."""
    bodies = []
    for _ in range(2):
        a = world.org("admin")
        p = engagement_payload()
        _confirm_false(p)
        r = world.create(a, copy.deepcopy(p))
        b = dict(r.json())
        for k in ("request_id", "instance", "ledger_seq"):
            b.pop(k, None)
        bodies.append(b)
    assert bodies[0] == bodies[1]
