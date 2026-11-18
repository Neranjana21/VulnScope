"""Stress: exclusion-beats-inclusion matrix with overlapping CIDRs and
wildcard-vs-apex domains.

Catalogue row: docs/stress-tests.md "Policy / scope guard" -> "Exclusion-
beats-inclusion matrix; overlapping CIDRs; wildcard domains vs apex."
Invariant under test (CLAUDE.md rule 3, decisions.md D8): no matter how
specific or broad scope.allow is, any overlapping scope.deny entry wins.
Supports: Slice 0 AC1, AC2.
"""
from __future__ import annotations

from datetime import UTC, datetime

from hypothesis import given, settings
from hypothesis import strategies as st

from vulnscope.policy.decide import decide
from vulnscope.policy.ratelimit import InMemoryRateLimitStore
from vulnscope.policy.types import Action, RuleId


def _decide_for(clock_factory, resolver_factory, engagement_factory, host, ip, allow, deny):
    engagement = engagement_factory(scope_allow=allow, scope_deny=deny)
    resolver = resolver_factory({host: (ip,)})
    clock = clock_factory(datetime(2026, 1, 15, tzinfo=UTC))
    store = InMemoryRateLimitStore()
    action = Action(kind="http", target=host, adapter="stress-test")
    return decide(
        action, engagement, clock.now(), resolver=resolver, clock=clock, rate_limit_store=store
    )


@given(
    third_octet=st.integers(min_value=0, max_value=255),
    fourth_octet=st.integers(min_value=1, max_value=254),
)
@settings(deadline=None, max_examples=100)
def test_nested_cidr_exclusion_always_wins(
    third_octet: int, fourth_octet: int, clock_factory, resolver_factory, engagement_factory
) -> None:
    """scope.allow is a broad /8 with the exact CIDR present in scope.allow
    (so D8's private-range special-case does not fire here -- see the
    wildcard tests below for why 10.0.0.0/8 is deliberately used only in
    this test). scope.deny nests progressively narrower CIDRs (/16, /24,
    /32) that all cover the same resolved address. Exclusion must win
    regardless of which overlapping deny entry is narrowest or whether it
    is more or less specific than the matching allow entry.
    """
    ip = f"10.{third_octet}.{fourth_octet}.1"
    host = f"host-{third_octet}-{fourth_octet}.lab.test"
    allow = ("10.0.0.0/8",)
    deny = (
        f"10.{third_octet}.0.0/16",
        f"10.{third_octet}.{fourth_octet}.0/24",
        f"{ip}/32",
    )

    decision = _decide_for(
        clock_factory, resolver_factory, engagement_factory, host, ip, allow, deny
    )
    assert not decision.allowed
    assert decision.rule_id == RuleId.EXCLUDED


def test_wildcard_allow_apex_deny(clock_factory, resolver_factory, engagement_factory) -> None:
    """scope.allow covers a wildcard subdomain pattern; scope.deny covers
    the apex domain only. A request to the apex itself must be denied; a
    request to a subdomain must remain allowed (a narrow apex-only deny must
    not leak into the wildcard's other members).

    IPs use TEST-NET-1 (RFC 5737, 192.0.2.0/24): reserved documentation
    space that is deliberately NOT RFC1918/CGNAT/ULA, so D8's private-range
    check never fires here -- this test is only about exclusion vs.
    wildcard/apex matching, not the private-range rule.
    """
    allow = ("*.lab.test",)
    deny = ("lab.test",)

    apex_decision = _decide_for(
        clock_factory, resolver_factory, engagement_factory, "lab.test", "192.0.2.1", allow, deny
    )
    assert not apex_decision.allowed
    # The apex is not actually covered by *.lab.test (wildcard != apex), so
    # OUT_OF_SCOPE is also an acceptable result here; EXCLUDED is acceptable
    # if the implementation treats the apex deny as matching regardless.
    # Either way it must not be allowed=True.
    assert apex_decision.rule_id in (RuleId.OUT_OF_SCOPE, RuleId.EXCLUDED)

    sub_decision = _decide_for(
        clock_factory, resolver_factory, engagement_factory,
        "sub.lab.test", "192.0.2.2", allow, deny,
    )
    assert sub_decision.allowed
    assert sub_decision.rule_id == RuleId.ALLOW


def test_wildcard_allow_apex_also_allowed_apex_excluded_by_name(
    clock_factory, resolver_factory, engagement_factory
) -> None:
    """When the apex IS also explicitly listed in scope.allow alongside the
    wildcard, and scope.deny excludes the apex by exact name, the apex
    request must still be denied (EXCLUDED) -- exclusion beats the explicit
    inclusion, not just the wildcard-implied one."""
    allow = ("*.lab.test", "lab.test")
    deny = ("lab.test",)

    apex_decision = _decide_for(
        clock_factory, resolver_factory, engagement_factory, "lab.test", "192.0.2.1", allow, deny
    )
    assert not apex_decision.allowed
    assert apex_decision.rule_id == RuleId.EXCLUDED

    sub_decision = _decide_for(
        clock_factory, resolver_factory, engagement_factory,
        "sub.lab.test", "192.0.2.2", allow, deny,
    )
    assert sub_decision.allowed
