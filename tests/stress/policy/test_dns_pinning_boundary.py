"""Stress: Resolver Protocol boundary -- resolution-change-between-check-
and-connect (DNS pinning).

Catalogue row: docs/stress-tests.md "Policy / scope guard" -> "DNS: name
that resolves to a denied address; resolution change between check and
connect (pinning test); CNAME into an excluded name."

Slice 0 has no real network connect (no gateway, no workers, D11), so there
is nothing to "pin" at a TCP-connect layer yet. What IS testable now is the
Resolver Protocol boundary inside decide(): a single decide() call must
resolve a hostname AT MOST ONCE and use that one resolution for every
downstream check (deny-list match, private-range match, expected_ip_ranges
match) -- never re-resolve mid-decision -- and two independently sequential
decide() calls for the same hostname must not share a resolution cache (D5's
"no shared mutable state"), so a resolver that changes its answer between
calls is reflected faithfully, not masked by stale state. This is the real,
testable-today analogue of the "resolution changes between check and
connect" TOCTOU scenario; the full network-level pinning test is an S1
concern once a real HTTP client exists.

Recheck note, round 1 (docs/gates/slice0-pre-stress-recheck.md, re the
plan's SEC-2 revision): the then-current check order in
docs/gates/slice0-plan.md Section 3.1 ran `scope.deny`/`scope.allow` as
PURE, pre-resolution checks against the raw target string only, with
nothing re-applying `scope.deny` to the *resolved* IP. That meant the
catalogue row this file is meant to cover -- "CNAME into an excluded name"
(docs/stress-tests.md) -- was not actually covered by any step, unless the
excluded range happened to also be caught by the always-deny or
private-range checks for an unrelated reason. This was filed as a new
finding in the round-1 recheck addendum, with one test documenting the
coincidental case and a second (deliberately failing-by-design) test
isolating the real gap with a public, non-private excluded range.

Recheck note, round 2 (docs/gates/slice0-pre-stress-recheck.md addendum,
this is the CLOSING update): the architect's second revision adds a new
§3.1 step 7 -- `scope.deny` is now re-checked against the resolved IP(s),
denying with `rule_id=EXCLUDED`, inserted right after the always-deny-list
check (step 6) and before the private-range check (now step 8). This
closes the gap directly and symmetrically for BOTH tests below: the
"coincidental private-range" case is no longer coincidental (step 7 now
fires first, before step 8 ever gets a chance to), and the public-range
case now has a real step that denies it. Both tests are updated below to
assert `rule_id=EXCLUDED` and to say so plainly -- the public-range test in
particular moves from "expected to fail by design" to "correctly
specified by the plan; still fails only because Task A has not been
implemented yet". The plan's own Task A test list independently names the
exact same scenario (`tests/unit/policy/test_decide_resolved_ip_against_scope_deny.py`,
same `203.0.113.0/24` TEST-NET-3 CIDR, same expected `allowed=False,
rule_id=EXCLUDED`) -- no conflict, no inconsistency between the two.
OQ-7 (whether `scope.allow` needs a symmetric resolved-IP re-check) remains
open and does not affect any assertion in this file, since nothing here
relies on `scope.allow` being resolution-sensitive.
"""
from __future__ import annotations

from datetime import UTC, datetime

from vulnscope.policy.decide import decide
from vulnscope.policy.ratelimit import InMemoryRateLimitStore
from vulnscope.policy.types import Action, RuleId


def test_decide_resolves_hostname_at_most_once_per_call(
    clock_factory, resolver_factory, engagement_factory
) -> None:
    host = "pinned.lab.test"
    engagement = engagement_factory(scope_allow=(host,))
    resolver = resolver_factory({host: ("192.0.2.10",)})
    clock = clock_factory(datetime(2026, 1, 15, tzinfo=UTC))
    store = InMemoryRateLimitStore()

    action = Action(kind="http", target=host, adapter="stress-test")
    decision = decide(
        action, engagement, clock.now(), resolver=resolver, clock=clock, rate_limit_store=store
    )

    assert decision.allowed
    assert resolver.calls.count(host) <= 1, (
        f"decide() called resolver.resolve({host!r}) {resolver.calls.count(host)} times; "
        "a single decision must use one resolution for every downstream check"
    )


def test_resolution_change_between_two_sequential_decisions_is_not_cached(
    clock_factory, resolver_factory, engagement_factory
) -> None:
    """Models the check-then-connect gap: the SAME hostname resolves to an
    allowed address on the first decide() call and to a denied (always-deny,
    D7) address on a second, later decide() call. If decide() or anything it
    is given cached resolutions across calls, the second call would wrongly
    reuse the first (allowed) answer instead of re-resolving and catching
    the now-denied address.
    """
    host = "shifting.lab.test"
    engagement = engagement_factory(scope_allow=(host,))
    clock = clock_factory(datetime(2026, 1, 15, tzinfo=UTC))
    store = InMemoryRateLimitStore()
    action = Action(kind="http", target=host, adapter="stress-test")

    first_resolver = resolver_factory({host: ("192.0.2.11",)})
    first_decision = decide(
        action, engagement, clock.now(),
        resolver=first_resolver, clock=clock, rate_limit_store=store,
    )
    assert first_decision.allowed
    assert first_decision.resolved_ips == ("192.0.2.11",)

    # Between check and (hypothetical) connect, the name now resolves into
    # the always-deny link-local metadata range (D7).
    second_resolver = resolver_factory({host: ("169.254.169.254",)})
    second_decision = decide(
        action, engagement, clock.now(),
        resolver=second_resolver, clock=clock, rate_limit_store=store,
    )
    assert not second_decision.allowed
    assert second_decision.rule_id == RuleId.DENY_ALWAYS_LIST
    assert second_decision.resolved_ips == ("169.254.169.254",)


def test_cname_into_excluded_private_range_is_denied_by_scope_deny_step(
    clock_factory, resolver_factory, engagement_factory
) -> None:
    """A hostname in scope.allow that (via CNAME, modeled here simply as a
    different A-record than the literal hostname) resolves into an RFC1918
    address range that is ALSO listed in scope.deny is denied `EXCLUDED` --
    via the plan's new step 7 (`scope.deny` re-checked against the resolved
    IP), which runs BEFORE the private-range check (step 8), so this is no
    longer merely coincidental overlap with the private-range rule (as it
    was before the plan's second revision added step 7 -- see
    docs/gates/slice0-pre-stress-recheck.md round 1 and round 2 notes).
    """
    host = "cname-source.lab.test"
    engagement = engagement_factory(scope_allow=(host,), scope_deny=("10.90.0.0/24",))
    resolver = resolver_factory({host: ("10.90.0.5",)})
    clock = clock_factory(datetime(2026, 1, 15, tzinfo=UTC))
    store = InMemoryRateLimitStore()
    action = Action(kind="http", target=host, adapter="stress-test")

    decision = decide(
        action, engagement, clock.now(), resolver=resolver, clock=clock, rate_limit_store=store
    )
    assert not decision.allowed
    assert decision.rule_id == RuleId.EXCLUDED, (
        "expected the new step 7 (scope.deny re-checked against the "
        "resolved IP) to fire before the private-range check -- if this "
        "returns DENY_PRIVATE_RANGE instead, step 7 is either missing or "
        "ordered after step 8, contrary to the plan"
    )


def test_cname_into_excluded_public_range_must_still_be_denied(
    clock_factory, resolver_factory, engagement_factory
) -> None:
    """Isolates the "CNAME into an excluded name" invariant
    (docs/stress-tests.md) from D8's private-range special case: scope.deny
    covers a PUBLIC, non-private, non-always-deny range (TEST-NET-3, RFC
    5737, 203.0.113.0/24); a hostname in scope.allow resolves into it via
    CNAME.

    STATUS (docs/gates/slice0-pre-stress-recheck.md, round 2): correctly
    specified by docs/gates/slice0-plan.md's current Section 3.1 step 7
    (`scope.deny` re-checked against the resolved IP(s) -> `EXCLUDED`,
    added specifically to close the gap this test first surfaced in round
    1). This is no longer "expected to fail by design" against the plan --
    the plan now agrees with this assertion exactly, including the
    rule_id. It still fails today only because Task A has not been
    implemented yet (this whole suite is pre-implementation); once Task A
    lands, this is a real pass/fail check, not a documented, accepted gap.
    The plan's own Task A test list independently names this exact
    scenario (`tests/unit/policy/test_decide_resolved_ip_against_scope_deny.py`,
    same CIDR, same expected result) -- no conflict between the two.
    """
    host = "cname-source-public.lab.test"
    engagement = engagement_factory(scope_allow=(host,), scope_deny=("203.0.113.0/24",))
    resolver = resolver_factory({host: ("203.0.113.5",)})
    clock = clock_factory(datetime(2026, 1, 15, tzinfo=UTC))
    store = InMemoryRateLimitStore()
    action = Action(kind="http", target=host, adapter="stress-test")

    decision = decide(
        action, engagement, clock.now(), resolver=resolver, clock=clock, rate_limit_store=store
    )
    assert not decision.allowed, (
        "a hostname resolving (e.g. via CNAME) into a scope.deny-covered "
        "public range was ALLOWED -- exclusions must beat inclusions for "
        "the resolved address too, not just the raw target string "
        "(CLAUDE.md rule 3; closed by plan §3.1 step 7)"
    )
    assert decision.rule_id == RuleId.EXCLUDED
