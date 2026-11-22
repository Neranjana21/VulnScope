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

from hypothesis import HealthCheck, given, settings
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
@settings(
    deadline=None,
    max_examples=100,
    # the fixtures are stateless factories (they return a class or function, never shared state)
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
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
    allow = ("10.0.0.0/8", host)
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


@given(
    third_octet=st.integers(min_value=0, max_value=255),
    fourth_octet=st.integers(min_value=1, max_value=253),
)
@settings(
    deadline=None,
    max_examples=100,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_nested_cidr_control_outside_exclusion_is_allowed(
    third_octet: int, fourth_octet: int, clock_factory, resolver_factory, engagement_factory
) -> None:
    """STR-A1 control case (owner-approved 2026-11-19). Same scope as
    test_nested_cidr_exclusion_always_wins: allow = (10.0.0.0/8, host), deny =
    nested /16, /24, /32 around 10.<t>.<f>.1. An address inside 10.0.0.0/8 that
    lies OUTSIDE every deny entry must be ALLOWED in the standard profile (the
    10.0.0.0/8 entry is a subnet of one private block, so it opts in per
    task-a-design.md section 2.2). This proves the exclusion test above is
    red/green for the right reason (exclusion is what denies, not a blanket
    private-range or scope denial) and that step 4 is not weakened: the host
    name itself is still listed explicitly in allow.
    """
    excluded_ip = f"10.{third_octet}.{fourth_octet}.1"
    deny = (
        f"10.{third_octet}.0.0/16",
        f"10.{third_octet}.{fourth_octet}.0/24",
        f"{excluded_ip}/32",
    )
    other_third = (third_octet + 1) % 256  # a different /16, so outside all three entries
    ip = f"10.{other_third}.{fourth_octet}.1"
    host = f"control-{third_octet}-{fourth_octet}.lab.test"
    allow = ("10.0.0.0/8", host)

    decision = _decide_for(
        clock_factory, resolver_factory, engagement_factory, host, ip, allow, deny
    )
    assert decision.allowed, "address outside the exclusion must be allowed (control)"
    assert decision.rule_id == RuleId.ALLOW
    assert ip in decision.resolved_ips


def test_nested_cidr_control_hostname_needs_its_own_allow_entry(
    clock_factory, resolver_factory, engagement_factory
) -> None:
    """STR-A1 control, step 4 not weakened: with ONLY the 10.0.0.0/8 CIDR in
    allow (the original line-51 tuple), a hostname is not covered by a CIDR
    entry (task-a-design.md section 2 step 4 / 8.1) and is denied OUT_OF_SCOPE,
    even though its resolved address is inside 10.0.0.0/8 and outside every
    exclusion. This is why the allow tuple of the exclusion test lists the host.
    """
    host = "control-only-cidr.lab.test"
    decision = _decide_for(
        clock_factory, resolver_factory, engagement_factory, host, "10.9.9.1",
        ("10.0.0.0/8",), ("10.5.0.0/16",),
    )
    assert not decision.allowed
    assert decision.rule_id == RuleId.OUT_OF_SCOPE


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
