"""Stress: long/looping simulated redirect chains through decide() (D12,
AC2).

Catalogue row: docs/stress-tests.md "Policy / scope guard" -> "Redirect
chains: allowed -> allowed -> denied; redirect loops; scheme downgrades."

decide() is pure/stateless per call (D5); chain-length and loop bounding is
the CALLER's job (a real redirect follower in S1; a test-side loop here).
These tests encode docs/gates/slice0-plan.md Section 3.1's PROPOSED
precedence for OQ-2 ("the underlying deny rule wins; REDIRECT_DENIED only
overrides a scope-only denial -- EXCLUDED/OUT_OF_SCOPE -- on a redirect
hop"). If the owner resolves OQ-2 differently, the affected assertions below
must change under R1 (an orchestrator-authorized stress-test edit), not be
silently reinterpreted by the implementer.

Recheck note, round 1 (docs/gates/slice0-pre-stress-recheck.md): the plan's
SEC-2 fix renumbered the check order (scope.deny/scope.allow are steps 3-4,
pre-resolution). The redirect-override rule's label precedence is
unchanged in substance -- "scope-only denial gets relabeled
REDIRECT_DENIED on a hop; every other denial keeps its own rule_id" -- so
every assertion below matches regardless of exact step numbers.

Recheck note, round 2 (docs/gates/slice0-pre-stress-recheck.md addendum):
the plan gained a new step 7 (`scope.deny` re-checked against the
*resolved* IP, closing the gap `test_dns_pinning_boundary.py` found) and
renumbered everything after it (private-range is now step 8,
`expected_ip_ranges` step 9, rate limit step 10, ALLOW step 11, the
redirect-override rule step 12). Step 12 now also triggers
`REDIRECT_DENIED` on step 7's denial, alongside steps 3-4 -- still just
"any scope.deny/scope.allow-flavoured denial", which is exactly the
EXCLUDED/OUT_OF_SCOPE grouping this file's assertions already depend on.
No hop in any test below actually exercises the new step 7 (none of this
file's `scope.deny` entries are non-empty), so step 7's addition does not
change any outcome here either -- confirmed by the IP-address note below.
No assertion changed, in either round.

Recheck note, IP addresses: originally used bare RFC1918 addresses
(10.x.x.x) for the "allowed" hops without an exact CIDR in scope.allow,
which D8's private-range step would actually deny as DENY_PRIVATE_RANGE
rather than ALLOW. Latent bug found during the STR-1 recheck, independent
of the plan revision; fixed by switching to TEST-NET-1 (RFC 5737,
192.0.2.0/24), which also is not covered by any `scope.deny` entry in this
file, so the new step 7 has nothing to match here either.
"""
from __future__ import annotations

from datetime import UTC, datetime

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from vulnscope.policy.decide import decide
from vulnscope.policy.ratelimit import InMemoryRateLimitStore
from vulnscope.policy.types import Action, RuleId

MAX_HOPS = 20  # caller-side cap a real redirect follower would enforce


def _run_chain(clock_factory, resolver_factory, engagement_factory, hosts, allowed_hosts):
    clock = clock_factory(datetime(2026, 1, 15, tzinfo=UTC))
    store = InMemoryRateLimitStore()
    engagement = engagement_factory(scope_allow=tuple(allowed_hosts))
    resolver = resolver_factory({h: (f"192.0.2.{i % 250 + 1}",) for i, h in enumerate(hosts)})

    results: list[RuleId] = []
    for hop_index, host in enumerate(hosts):
        if hop_index >= MAX_HOPS:
            break
        action = Action(
            kind="http", target=host, adapter="stress-test", is_redirect_hop=hop_index > 0
        )
        decision = decide(
            action,
            engagement,
            clock.now(),
            resolver=resolver,
            clock=clock,
            rate_limit_store=store,
        )
        results.append(decision.rule_id)
        if not decision.allowed:
            break
    return results


def test_long_allowed_chain_bounded_by_hop_cap(
    clock_factory, resolver_factory, engagement_factory
) -> None:
    """depth is one past MAX_HOPS to prove the cap -- not decide() itself --
    is what stops the walk, even though every hop is individually ALLOW."""
    hosts = [f"ok{i}.lab.test" for i in range(MAX_HOPS + 1)]
    allowed_hosts = set(hosts)
    results = _run_chain(clock_factory, resolver_factory, engagement_factory, hosts, allowed_hosts)
    assert len(results) == MAX_HOPS
    assert all(r == RuleId.ALLOW for r in results)


def test_first_hop_denied_reports_out_of_scope_not_redirect_denied(
    clock_factory, resolver_factory, engagement_factory
) -> None:
    """Hop 0 is never a redirect hop (is_redirect_hop=False) -- a denial
    there must keep its own rule_id, not REDIRECT_DENIED."""
    results = _run_chain(
        clock_factory, resolver_factory, engagement_factory, ["denied.lab.test"], set()
    )
    assert results == [RuleId.OUT_OF_SCOPE]


def test_later_hop_denied_reports_redirect_denied_per_oq2(
    clock_factory, resolver_factory, engagement_factory
) -> None:
    hosts = ["ok0.lab.test", "ok1.lab.test", "denied.lab.test", "ok2.lab.test"]
    allowed_hosts = {"ok0.lab.test", "ok1.lab.test", "ok2.lab.test"}
    results = _run_chain(clock_factory, resolver_factory, engagement_factory, hosts, allowed_hosts)
    assert results == [RuleId.ALLOW, RuleId.ALLOW, RuleId.REDIRECT_DENIED]


def test_redirect_loop_is_bounded_by_caller_hop_cap(
    clock_factory, resolver_factory, engagement_factory
) -> None:
    """A redirect loop (a -> b -> a -> b -> ...) must not hang decide() or
    the caller; the caller-side MAX_HOPS cap is what terminates it, since
    decide() itself has no chain memory (stateless per call, D5)."""
    loop_hosts = (["a.lab.test", "b.lab.test"] * (MAX_HOPS * 5))[: MAX_HOPS * 5]
    allowed_hosts = {"a.lab.test", "b.lab.test"}
    results = _run_chain(
        clock_factory, resolver_factory, engagement_factory, loop_hosts, allowed_hosts
    )
    assert len(results) == MAX_HOPS
    assert all(r == RuleId.ALLOW for r in results)


@given(hop_outcomes=st.lists(st.booleans(), min_size=1, max_size=200))
@settings(
    deadline=None,
    max_examples=50,
    # the fixtures are stateless factories (they return a class or function, never shared state)
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_property_chain_stops_at_first_denied_hop(
    hop_outcomes: list[bool], clock_factory, resolver_factory, engagement_factory
) -> None:
    """For any boolean sequence of 'should this hop be allowed', build a
    host chain matching it and assert the chain walk stops at the first
    False (or completes, bounded by MAX_HOPS, if all True) -- independent of
    sequence length or pattern."""
    hosts = []
    allowed_hosts = set()
    first_false = None
    for i, ok in enumerate(hop_outcomes):
        host = f"h{i}.lab.test"
        hosts.append(host)
        if ok:
            allowed_hosts.add(host)
        elif first_false is None:
            first_false = i

    capped_hosts = hosts[:MAX_HOPS]
    results = _run_chain(
        clock_factory, resolver_factory, engagement_factory, capped_hosts, allowed_hosts
    )

    if first_false is None or first_false >= MAX_HOPS:
        assert len(results) == len(capped_hosts)
        assert all(r == RuleId.ALLOW for r in results)
    else:
        assert len(results) == first_false + 1
        expected_last = RuleId.OUT_OF_SCOPE if first_false == 0 else RuleId.REDIRECT_DENIED
        assert results[-1] == expected_last
        assert all(r == RuleId.ALLOW for r in results[:-1])
