"""PA-1b: Action.adapter is validated before any work (it lands in the ledger)."""

from __future__ import annotations

import pytest
from policy_test_support import NOW, FakeChainBackend, FixedClock, MapResolver, make_view

from vulnscope.policy.decide_and_record import decide_and_record
from vulnscope.policy.denylist import compute_policy_version
from vulnscope.policy.ratelimit import InMemoryRateLimitStore
from vulnscope.policy.types import Action

H = "a.lab.test"
VERSION = compute_policy_version(lab_enabled=False, lab_cidr=None)


async def _call(adapter: str, backend: FakeChainBackend, resolver: MapResolver):
    return await decide_and_record(
        Action(kind="http", target=H, adapter=adapter),
        make_view(policy_version=VERSION, scope_allow=(H,)),
        NOW,
        resolver=resolver,
        clock=FixedClock(NOW),
        rate_limit_store=InMemoryRateLimitStore(),
        chain_backend=backend,
        actor="system",
    )


GOOD = [
    "unit",
    "stress-test",
    "api.scan_create",
    "api.scan_create.lifecycle",
    "security_headers@1",
    "security_headers@1|job=0193-abc_DEF|req=r-42",
    "orchestrator|job=j1",
    "x" * 64,
]
BAD = [
    "tok=abc123secret",
    "name|tok=abc123secret",
    "name|job=a|req=b|extra=c",
    "has space",
    "tab\there",
    "nl\nx",
    "bell\x07",
    "\u202eevil",
    "caf\u00e9",
    "",
    "x" * 65,
    "ok|job=" + "y" * 65,
    "Bearer abc.def",
    "a|job=",
]


@pytest.mark.parametrize("adapter", GOOD)
async def test_expected_adapter_strings_pass(adapter: str) -> None:
    backend = FakeChainBackend()
    d = await _call(adapter, backend, MapResolver({H: ("192.0.2.1",)}))
    assert d.allowed and len(backend.appended) == 1


@pytest.mark.parametrize("adapter", BAD)
async def test_bad_adapter_raises_before_any_work(adapter: str) -> None:
    backend, resolver = FakeChainBackend(), MapResolver({H: ("192.0.2.1",)})
    with pytest.raises(ValueError):
        await _call(adapter, backend, resolver)
    assert backend.appended == [] and backend.head_calls == 0 and resolver.calls == []


async def test_non_str_adapter_raises() -> None:
    backend = FakeChainBackend()
    with pytest.raises(ValueError):
        await _call(None, backend, MapResolver({}))  # type: ignore[arg-type]
    assert backend.appended == []
