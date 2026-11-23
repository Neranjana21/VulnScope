"""PA-8: two decide() calls never share a resolution (no cross-call cache, D5)."""

from __future__ import annotations

from policy_test_support import MapResolver, run_decide

from vulnscope.policy.ratelimit import InMemoryRateLimitStore
from vulnscope.policy.types import RuleId

H = "a.lab.test"


def test_second_call_re_resolves_and_sees_the_new_answer() -> None:
    resolver = MapResolver({H: ("192.0.2.1",)})
    store = InMemoryRateLimitStore()
    first, _ = run_decide(H, resolver=resolver, store=store, allow=(H,))
    resolver.table[H] = ("169.254.169.254",)
    second, _ = run_decide(H, resolver=resolver, store=store, allow=(H,))
    assert resolver.calls == [H, H]
    assert first.allowed and first.resolved_ips == ("192.0.2.1",)
    assert second.rule_id == RuleId.DENY_ALWAYS_LIST
    assert second.resolved_ips == ("169.254.169.254",)
