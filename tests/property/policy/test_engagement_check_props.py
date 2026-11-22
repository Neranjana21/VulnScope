"""Hypothesis checks for policy/engagement_check.py (design 11.4)."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

from hypothesis import given, settings
from hypothesis import strategies as st

from vulnscope.policy.decide import decide
from vulnscope.policy.engagement_check import validate_engagement_targets
from vulnscope.policy.ratelimit import InMemoryRateLimitStore
from vulnscope.policy.types import Action, EngagementPolicyView

NOW = datetime(2026, 1, 15, tzinfo=UTC)

LITERALS = [
    "192.0.2.1",
    "203.0.113.9",
    "8.8.8.8",
    "10.1.2.3",
    "10.9.9.9",
    "172.16.5.5",
    "192.168.0.7",
    "100.64.1.1",
    "100.100.100.200",
    "169.254.169.254",
    "127.0.0.1",
    "0.0.0.5",
    "240.0.0.1",
    "224.0.0.9",
    "2001:db8::1",
    "fd12::5",
    "fe80::1",
    "::1",
    "64:ff9b::a9fe:a9fe",
    "64:ff9b::808:808",
    "2002:a9fe:a9fe::1",
    "::ffff:10.1.2.3",
    "198.51.100.77",
]
ALLOW_POOL = [
    "0.0.0.0/0",
    "::/0",
    "192.0.2.0/24",
    "203.0.113.0/24",
    "10.0.0.0/8",
    "10.1.0.0/16",
    "172.16.0.0/12",
    "100.64.0.0/10",
    "fc00::/7",
    "127.0.0.0/8",
    "198.51.100.0/24",
    "2001:db8::/32",
    "8.8.8.8",
    "::1",
]
DENY_POOL = ["10.1.2.0/24", "192.0.2.0/25", "203.0.113.9", "198.51.100.0/24", "::ffff:10.9.0.0/112"]


class _Clock:
    def now(self) -> datetime:
        return NOW

    def monotonic(self) -> float:
        return 0.0


class _Res:
    def resolve(self, hostname: str) -> tuple[str, ...]:  # never used for literals
        raise AssertionError("literals must not resolve")


@given(
    st.sampled_from(LITERALS),
    st.lists(st.sampled_from(ALLOW_POOL), max_size=5),
    st.lists(st.sampled_from(DENY_POOL), max_size=3),
    st.sampled_from([("standard", False, None), ("lab", True, None), ("lab", True, "10.1.0.0/16")]),
)
@settings(max_examples=400, deadline=None)
def test_check_agrees_with_decide_for_ip_literals(lit, allow, deny, prof) -> None:
    profile, lab_enabled, lab_cidr = prof
    allow_t = tuple(a for a in allow)
    issues = validate_engagement_targets(
        domains=[lit],
        ip_ranges=[],
        allow=allow_t,
        deny=deny,
        expected_ip_ranges=[],
        profile=profile,
        lab_enabled=lab_enabled,
        lab_cidr=lab_cidr,
    )
    view = EngagementPolicyView(
        engagement_id="eng-1",
        org_id="o",
        profile=profile,
        status="active",
        scope_allow=allow_t,
        scope_deny=tuple(deny),
        expected_ip_ranges=(),
        rate_limit_rps=1e6,
        window_not_before=NOW - timedelta(days=1),
        window_not_after=NOW + timedelta(days=1),
        policy_version="1.0.0+prop",
    )
    d = decide(
        Action("http", lit, "prop"),
        view,
        NOW,
        resolver=_Res(),
        clock=_Clock(),
        rate_limit_store=InMemoryRateLimitStore(),
        lab_enabled=lab_enabled,
        lab_cidr=lab_cidr,
    )
    assert (issues == ()) == d.allowed, (lit, allow, deny, prof, d.rule_id)


@given(
    st.lists(st.text(max_size=40), max_size=6),
    st.lists(st.text(max_size=40), max_size=6),
    st.lists(st.text(max_size=40), max_size=6),
    st.lists(st.text(max_size=40), max_size=4),
)
@settings(max_examples=300, deadline=None)
def test_hostile_text_never_raises_and_never_echoes(domains, ranges, allow, deny) -> None:
    issues = validate_engagement_targets(
        domains=domains,
        ip_ranges=ranges,
        allow=allow,
        deny=deny,
        expected_ip_ranges=[],
        profile="standard",
    )
    for i in issues:
        assert re.fullmatch(r"[A-Za-z0-9_:.\-]*", i.code)
        assert -1 <= i.index < max(len(domains), len(ranges), len(allow), len(deny), 1)


@given(st.lists(st.text(max_size=5), min_size=257, max_size=260))
@settings(max_examples=5, deadline=None)
def test_list_caps_give_one_limit_issue(entries) -> None:
    issues = validate_engagement_targets(
        domains=[],
        ip_ranges=[],
        allow=entries,
        deny=[],
        expected_ip_ranges=[],
        profile="standard",
    )
    assert [(i.rule, i.code, i.index) for i in issues] == [("LIMIT", "TOO_MANY", -1)]
