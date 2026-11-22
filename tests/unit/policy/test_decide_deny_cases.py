"""AC1: one case per RuleId plus input-guard and status/window ordering cases."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from policy_test_support import (
    NOW,
    WINDOW_END,
    WINDOW_START,
    FixedClock,
    MapResolver,
    RaisingResolver,
    RawResolver,
    make_view,
    run_decide,
)

from vulnscope.policy.decide import decide
from vulnscope.policy.ratelimit import InMemoryRateLimitStore
from vulnscope.policy.types import Action, RuleId

H = "a.lab.test"
TABLE = {H: ("192.0.2.1",)}


def test_allow() -> None:
    d, _ = run_decide(H, allow=(H,), table=TABLE)
    assert d.allowed and d.rule_id == RuleId.ALLOW
    assert d.resolved_ips == ("192.0.2.1",)
    assert d.ts == NOW and d.ledger_seq is None
    assert d.policy_version == "1.0.0+teststub"
    assert d.action.target == H


def test_decision_keeps_original_action_object() -> None:
    action = Action(kind="http", target="A.Lab.Test.", adapter="x")
    d = decide(
        action,
        make_view(scope_allow=(H,)),
        NOW,
        resolver=MapResolver(TABLE),
        clock=FixedClock(),
        rate_limit_store=InMemoryRateLimitStore(),
    )
    assert d.action is action
    assert d.allowed


def test_always_list() -> None:
    d, _ = run_decide("169.254.169.254", allow=("0.0.0.0/0",))
    assert d.rule_id == RuleId.DENY_ALWAYS_LIST


def test_private() -> None:
    d, _ = run_decide("10.0.0.5", allow=("0.0.0.0/0",))
    assert d.rule_id == RuleId.DENY_PRIVATE_RANGE


def test_excluded_by_name_and_ip() -> None:
    d, r = run_decide(H, allow=(H,), deny=(H,), table=TABLE)
    assert d.rule_id == RuleId.EXCLUDED and r.calls == []
    d, r = run_decide("192.0.2.9", allow=("192.0.2.0/24",), deny=("192.0.2.9",))
    assert d.rule_id == RuleId.EXCLUDED


def test_out_of_scope() -> None:
    d, r = run_decide(H, allow=("other.lab.test",), table=TABLE)
    assert d.rule_id == RuleId.OUT_OF_SCOPE and r.calls == []


def test_expired_and_not_yet_valid_and_boundaries() -> None:
    d, _ = run_decide(H, allow=(H,), table=TABLE, now=WINDOW_END + timedelta(microseconds=1))
    assert d.rule_id == RuleId.EXPIRED
    d, _ = run_decide(H, allow=(H,), table=TABLE, now=WINDOW_START - timedelta(microseconds=1))
    assert d.rule_id == RuleId.NOT_YET_VALID
    for edge in (WINDOW_START, WINDOW_END):
        d, _ = run_decide(H, allow=(H,), table=TABLE, now=edge)
        assert d.allowed, "both window ends are inclusive"


def test_non_utc_offsets() -> None:
    tz = timezone(timedelta(hours=5, minutes=30))
    inside = (WINDOW_END - timedelta(hours=1)).astimezone(tz)
    d, _ = run_decide(H, allow=(H,), table=TABLE, now=inside)
    assert d.allowed and d.ts.utcoffset() == timedelta(0)
    outside = (WINDOW_END + timedelta(seconds=1)).astimezone(tz)
    d, _ = run_decide(H, allow=(H,), table=TABLE, now=outside)
    assert d.rule_id == RuleId.EXPIRED


def test_revoked_and_unknown_status_fail_closed() -> None:
    d, _ = run_decide(H, allow=(H,), table=TABLE, status="revoked")
    assert d.rule_id == RuleId.REVOKED
    d, r = run_decide(H, allow=(H,), table=TABLE, status="paused")
    assert d.rule_id == RuleId.REVOKED and r.calls == []


def test_rate() -> None:
    store = InMemoryRateLimitStore()
    clock = FixedClock()
    kw = dict(allow=(H,), table=TABLE, rate_limit_rps=1.0, store=store, clock=clock)
    first, _ = run_decide(H, **kw)
    second, _ = run_decide(H, **kw)
    assert first.allowed and second.rule_id == RuleId.RATE


def test_denied_calls_do_not_consume_tokens() -> None:
    store = InMemoryRateLimitStore()
    for _ in range(5):
        d, _ = run_decide(H, allow=(), table=TABLE, rate_limit_rps=1.0, store=store)
        assert d.rule_id == RuleId.OUT_OF_SCOPE
    d, _ = run_decide(H, allow=(H,), table=TABLE, rate_limit_rps=1.0, store=store)
    assert d.allowed


def test_resolved_outside_expected() -> None:
    d, _ = run_decide(H, allow=(H,), table=TABLE, expected_ip_ranges=("203.0.113.0/24",))
    assert d.rule_id == RuleId.RESOLVED_OUTSIDE_EXPECTED
    d, _ = run_decide(
        H,
        allow=(H,),
        table={H: ("203.0.113.9", "192.0.2.1")},
        expected_ip_ranges=("203.0.113.0/24",),
    )
    assert d.rule_id == RuleId.RESOLVED_OUTSIDE_EXPECTED, "every IP must be inside"
    d, _ = run_decide(
        H, allow=(H,), table={H: ("203.0.113.9",)}, expected_ip_ranges=("203.0.113.0/24",)
    )
    assert d.allowed


def test_redirect_relabel_only_for_steps_3_4_7() -> None:
    d, _ = run_decide(H, allow=(), table=TABLE, redirect=True)
    assert d.rule_id == RuleId.REDIRECT_DENIED
    d, _ = run_decide(H, allow=(H,), deny=(H,), table=TABLE, redirect=True)
    assert d.rule_id == RuleId.REDIRECT_DENIED
    d, _ = run_decide(H, allow=(H,), deny=("192.0.2.0/24",), table=TABLE, redirect=True)
    assert d.rule_id == RuleId.REDIRECT_DENIED
    d, _ = run_decide("169.254.169.254", allow=("0.0.0.0/0",), redirect=True)
    assert d.rule_id == RuleId.DENY_ALWAYS_LIST
    d, _ = run_decide("10.0.0.5", allow=("0.0.0.0/0",), redirect=True)
    assert d.rule_id == RuleId.DENY_PRIVATE_RANGE
    d, _ = run_decide(H, allow=(H,), table=TABLE, redirect=True, status="revoked")
    assert d.rule_id == RuleId.REVOKED
    d, _ = run_decide(H, allow=(H,), table={}, redirect=True)
    assert d.rule_id == RuleId.RESOLUTION_FAILED
    d, _ = run_decide("bad host", allow=(H,), redirect=True)
    assert d.rule_id == RuleId.OUT_OF_SCOPE


def test_resolution_failed_variants() -> None:
    for resolver in (
        MapResolver({}),
        RaisingResolver(RuntimeError("boom")),
        RaisingResolver(OSError("net")),
        RawResolver(()),
        RawResolver(["not-an-ip"]),
        RawResolver(["fe80::1%eth0"]),
        RawResolver("192.0.2.1"),
        RawResolver(None),
        RawResolver([5]),
        RawResolver(tuple(f"192.0.2.{i}" for i in range(1, 34))),
        RawResolver(["192.0.2.1", "127.1"]),
    ):
        d, _ = run_decide(H, allow=(H,), resolver=resolver)
        assert d.rule_id == RuleId.RESOLUTION_FAILED, resolver
        assert not d.allowed
        assert "boom" not in d.reason


def test_resolver_returning_mapped_form_is_collapsed() -> None:
    d, _ = run_decide(H, allow=(H,), table={H: ("::ffff:169.254.169.254",)})
    assert d.rule_id == RuleId.DENY_ALWAYS_LIST
    assert d.resolved_ips == ("169.254.169.254",)


def test_resolver_answer_with_embedded_metadata_denied() -> None:
    d, _ = run_decide(H, allow=(H,), table={H: ("64:ff9b::a9fe:a9fe",)})
    assert d.rule_id == RuleId.DENY_ALWAYS_LIST
    d, _ = run_decide(H, allow=(H,), deny=("203.0.113.0/24",), table={H: ("64:ff9b::cb00:7105",)})
    assert d.rule_id == RuleId.EXCLUDED


def test_unparseable_targets_deny_and_never_echo() -> None:
    for raw in ("a b", "http://[::1", "ftp://x", "a\x00b", "‮"):
        d, r = run_decide(raw, allow=(H,))
        assert d.rule_id == RuleId.OUT_OF_SCOPE
        assert d.reason.startswith("UNPARSEABLE_TARGET:")
        assert raw not in d.reason and r.calls == []


def test_empty_and_overlong_keep_status_ids() -> None:
    long = "a" * 2049
    for status_kw, target, expected in (
        (dict(status="revoked"), "", RuleId.REVOKED),
        (dict(), "", RuleId.OUT_OF_SCOPE),
        (dict(), long, RuleId.OUT_OF_SCOPE),
    ):
        d, r = run_decide(target, allow=(H,), **status_kw)
        assert d.rule_id == expected and r.calls == []
    d, _ = run_decide(long, allow=(H,), now=WINDOW_END + timedelta(seconds=1))
    assert d.rule_id == RuleId.EXPIRED
    d, _ = run_decide("", allow=(H,), now=WINDOW_START - timedelta(seconds=1))
    assert d.rule_id == RuleId.NOT_YET_VALID
    d, _ = run_decide(long, allow=(H,))
    assert d.reason == "UNPARSEABLE_TARGET:length"


def test_programming_errors_raise() -> None:
    clock, res, store = FixedClock(), MapResolver(TABLE), InMemoryRateLimitStore()
    view = make_view(scope_allow=(H,))
    good = Action(kind="http", target=H, adapter="x")

    def call(action=good, now=NOW):
        return decide(action, view, now, resolver=res, clock=clock, rate_limit_store=store)

    with pytest.raises(ValueError):
        call(now=datetime(2026, 1, 15))
    with pytest.raises(TypeError):
        call(action=Action(kind="http", target=None, adapter="x"))  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        call(action=Action(kind="http", target=b"a.lab.test", adapter="x"))  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        call(action=Action(kind="smtp", target=H, adapter="x"))  # type: ignore[arg-type]
    assert res.calls == []


def test_kinds_are_accepted() -> None:
    for kind in ("http", "tcp", "dns"):
        d, _ = run_decide(H, allow=(H,), table=TABLE, kind=kind)
        assert d.allowed
