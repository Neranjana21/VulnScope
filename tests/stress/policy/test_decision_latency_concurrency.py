"""Stress: policy decision latency p99 under concurrent calls, and absence
of shared mutable state across concurrent decide() calls.

Catalogue row: docs/stress-tests.md "Policy / scope guard" ->
"Throughput: decision latency p99 under concurrent calls; no shared mutable
state."
Budget: docs/decisions.md R6 "policy decision p99 < 5 ms with cached DNS".
Supports: Slice 0 AC1, AC2 (same decide() call path; this file does not
re-prove the rule_id matrix, that is tests/unit/policy/'s job).

D5 requires `decide()` to be a pure function over injected Resolver/Clock/
RateLimitStore, with "no shared mutable state" meaning no MODULE-level
mutable state -- an InMemoryRateLimitStore INSTANCE is explicit, injected
state, and is exactly what gets shared across threads here on purpose, to
prove it does not corrupt unrelated engagements' decisions under load.

Recheck note (docs/gates/slice0-pre-stress-recheck.md): this file calls
`decide()` directly, not the plan's new `decide_and_record()` wrapper
(§3.1.1). That is intentional, not an oversight -- the structural
one-call-site rule (`tests/unit/test_decide_call_sites.py`) only scans
`src/vulnscope/**/*.py` (production code); a test file benchmarking the
pure decision function's own latency is not a production call site, and
the R6 budget under test here ("policy decision p99 < 5ms") is specifically
about `decide()`'s own cost, not the cost of also appending to a
`ChainBackend` (that combined cost is a different, not-yet-written budget
and would need its own test against `decide_and_record()` with a real or
fake `chain_backend` argument).

Recheck note, IP addresses: the original version of this file used bare
RFC1918 addresses (10.x.x.x) for cases expected to resolve ALLOW, without
listing an exact matching CIDR in `scope.allow`. Per D8 / the plan's
private-range step (step 8 as of the round-2 renumbering below; step 7 at
the time this bug was found), that combination is actually
`DENY_PRIVATE_RANGE`, not `ALLOW` -- a latent bug in this file found during
the STR-1 recheck, independent of the plan revision itself, now fixed by
using TEST-NET-1 (RFC 5737, 192.0.2.0/24) addresses, which are not
RFC1918/CGNAT/ULA and not on the always-deny list, and are not listed in
any `scope.deny` entry in this file either (so the round-2 `scope.deny`
resolved-IP re-check, step 7, has nothing to match here -- still ALLOW).
"""
from __future__ import annotations

import statistics
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from vulnscope.policy.decide import decide
from vulnscope.policy.ratelimit import InMemoryRateLimitStore
from vulnscope.policy.types import Action, RuleId

N_ENGAGEMENTS = 50
CALLS_PER_ENGAGEMENT = 40
P99_BUDGET_SECONDS = 0.005  # R6: policy decision p99 < 5 ms with cached DNS
CI_SLACK_MULTIPLIER = 10  # generous slack for shared/virtualised CI hardware;
# record the MEASURED number in the post-gate regardless of pass/fail.


def test_decide_p99_latency_under_concurrency(clock_factory, resolver_factory, engagement_factory) -> None:
    """Many threads call decide() concurrently, each with its own
    engagement/host pair but a single shared InMemoryRateLimitStore
    instance. Every call must return the correct, engagement-specific
    decision (a shared-mutable-state bug would show up as cross-talk, not
    just as slow latency) and the overall p99 is measured against R6.
    """
    clock = clock_factory(datetime(2026, 1, 15, tzinfo=timezone.utc))
    store = InMemoryRateLimitStore()  # one shared instance, many threads

    cases = []
    for i in range(N_ENGAGEMENTS):
        host = f"host{i}.lab.test"
        engagement = engagement_factory(engagement_id=f"eng-{i}", scope_allow=(host,))
        resolver = resolver_factory({host: (f"192.0.2.{i % 250 + 1}",)})
        cases.append((engagement, resolver, host))

    latencies: list[float] = []
    errors: list[BaseException] = []

    def worker(case: tuple) -> None:
        engagement, resolver, host = case
        for _ in range(CALLS_PER_ENGAGEMENT):
            action = Action(kind="http", target=host, adapter="stress-test")
            start = time.perf_counter()
            try:
                decision = decide(
                    action,
                    engagement,
                    clock.now(),
                    resolver=resolver,
                    clock=clock,
                    rate_limit_store=store,
                )
            except BaseException as exc:  # noqa: BLE001 - captured for the report
                errors.append(exc)
                continue
            latencies.append(time.perf_counter() - start)
            assert decision.rule_id == RuleId.ALLOW
            assert decision.action.target == host

    with ThreadPoolExecutor(max_workers=16) as pool:
        list(pool.map(worker, cases))

    assert not errors, f"{len(errors)} decide() calls raised: {errors[:3]!r}"
    assert len(latencies) == N_ENGAGEMENTS * CALLS_PER_ENGAGEMENT

    latencies.sort()
    p50 = statistics.median(latencies)
    p99 = latencies[int(len(latencies) * 0.99) - 1]
    print(
        f"decide() latency under concurrency: n={len(latencies)} "
        f"p50={p50 * 1000:.3f}ms p99={p99 * 1000:.3f}ms"
    )

    budget = P99_BUDGET_SECONDS * CI_SLACK_MULTIPLIER
    assert p99 < budget, (
        f"p99={p99 * 1000:.3f}ms exceeds the CI-adjusted budget {budget * 1000:.1f}ms "
        f"(R6 target: {P99_BUDGET_SECONDS * 1000:.0f}ms)"
    )


def test_rate_limit_store_no_cross_engagement_leakage(clock_factory, resolver_factory, engagement_factory) -> None:
    """A single InMemoryRateLimitStore instance is shared across many
    concurrently-decided engagements; one engagement's target hitting its
    rate ceiling must never throttle a different engagement's target (which
    would indicate a rate-limit-key collision / shared-mutable-state bug,
    D5).
    """
    clock = clock_factory(datetime(2026, 1, 15, tzinfo=timezone.utc))
    store = InMemoryRateLimitStore()

    busy_host = "busy.lab.test"
    busy_engagement = engagement_factory(
        engagement_id="busy-eng", scope_allow=(busy_host,), rate_limit_rps=1.0
    )
    busy_resolver = resolver_factory({busy_host: ("198.51.100.1",)})

    def hammer_busy(_: int) -> RuleId:
        action = Action(kind="http", target=busy_host, adapter="stress-test")
        decision = decide(
            action,
            busy_engagement,
            clock.now(),
            resolver=busy_resolver,
            clock=clock,
            rate_limit_store=store,
        )
        return decision.rule_id

    with ThreadPoolExecutor(max_workers=8) as pool:
        busy_results = list(pool.map(hammer_busy, range(200)))

    assert RuleId.RATE in busy_results, (
        "expected at least one RATE decision once the busy engagement's "
        "ceiling is exceeded under concurrent load"
    )

    other_host = "quiet.lab.test"
    other_engagement = engagement_factory(
        engagement_id="quiet-eng", scope_allow=(other_host,), rate_limit_rps=1000.0
    )
    other_resolver = resolver_factory({other_host: ("198.51.100.2",)})
    other_action = Action(kind="http", target=other_host, adapter="stress-test")
    other_decision = decide(
        other_action,
        other_engagement,
        clock.now(),
        resolver=other_resolver,
        clock=clock,
        rate_limit_store=store,
    )
    assert other_decision.rule_id == RuleId.ALLOW
