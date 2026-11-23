"""AC2: hop-by-hop re-check in a simulated redirect chain (S0 proves the library half)."""

from __future__ import annotations

from policy_test_support import FixedClock, MapResolver, run_decide

from vulnscope.policy.ratelimit import InMemoryRateLimitStore
from vulnscope.policy.types import RuleId

MAX_HOPS = 10


def _walk(hosts: list[str], allow: tuple[str, ...], table: dict[str, tuple[str, ...]], **kw):
    store, clock, resolver = InMemoryRateLimitStore(), FixedClock(), MapResolver(table)
    out: list[RuleId] = []
    for i, h in enumerate(hosts[:MAX_HOPS]):
        d, _ = run_decide(
            h, allow=allow, resolver=resolver, store=store, clock=clock, redirect=i > 0, **kw
        )
        out.append(d.rule_id)
        if not d.allowed:
            break
    return out, resolver


def test_allowed_allowed_denied() -> None:
    table = {"a.lab.test": ("192.0.2.1",), "b.lab.test": ("192.0.2.2",)}
    out, resolver = _walk(
        ["a.lab.test", "b.lab.test", "evil.lab.test"], ("a.lab.test", "b.lab.test"), table
    )
    assert out == [RuleId.ALLOW, RuleId.ALLOW, RuleId.REDIRECT_DENIED]
    assert "evil.lab.test" not in resolver.calls


def test_loop_is_capped_by_the_caller() -> None:
    table = {"a.lab.test": ("192.0.2.1",), "b.lab.test": ("192.0.2.2",)}
    out, _ = _walk(["a.lab.test", "b.lab.test"] * 20, ("a.lab.test", "b.lab.test"), table)
    assert len(out) == MAX_HOPS and set(out) == {RuleId.ALLOW}


def test_other_denials_keep_their_id_on_a_hop() -> None:
    table = {
        "a.lab.test": ("192.0.2.1",),
        "meta.lab.test": ("169.254.169.254",),
        "priv.lab.test": ("10.0.0.5",),
        "gone.lab.test": ("192.0.2.9",),
    }
    allow = tuple(table)
    out, _ = _walk(["a.lab.test", "meta.lab.test"], allow, table)
    assert out[-1] == RuleId.DENY_ALWAYS_LIST
    out, _ = _walk(["a.lab.test", "priv.lab.test"], allow, table)
    assert out[-1] == RuleId.DENY_PRIVATE_RANGE
    out, _ = _walk(["a.lab.test", "nores.lab.test"], (*allow, "nores.lab.test"), table)
    assert out[-1] == RuleId.RESOLUTION_FAILED
    out, _ = _walk(["a.lab.test", "metadata"], allow, table)
    assert out[-1] == RuleId.DENY_ALWAYS_LIST
    out, _ = _walk(["a.lab.test", "ftp://a.lab.test"], allow, table)
    assert out[-1] == RuleId.OUT_OF_SCOPE


def test_relabel_for_resolved_level_exclusion() -> None:
    table = {"a.lab.test": ("192.0.2.1",), "x.lab.test": ("203.0.113.9",)}
    out, _ = _walk(
        ["a.lab.test", "x.lab.test"], tuple(table), table, scope_deny=("203.0.113.0/24",)
    )
    assert out == [RuleId.ALLOW, RuleId.REDIRECT_DENIED]


def test_revocation_between_hops_flips_the_next_hop() -> None:
    table = {"a.lab.test": ("192.0.2.1",), "b.lab.test": ("192.0.2.2",)}
    first, _ = run_decide("a.lab.test", allow=tuple(table), table=table)
    second, _ = run_decide(
        "b.lab.test", allow=tuple(table), table=table, redirect=True, status="revoked"
    )
    assert first.allowed and second.rule_id == RuleId.REVOKED
