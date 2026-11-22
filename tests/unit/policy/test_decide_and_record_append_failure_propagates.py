"""Fail closed (rule 8): an append failure or cancellation returns no decision.

DEPENDS ON Task B (`ledger.canonical`) through decide_and_record's import.
"""

from __future__ import annotations

import asyncio

import pytest
from policy_test_support import NOW, FakeChainBackend, FixedClock, MapResolver, make_view

from vulnscope.policy.decide_and_record import decide_and_record
from vulnscope.policy.denylist import compute_policy_version
from vulnscope.policy.ratelimit import InMemoryRateLimitStore
from vulnscope.policy.types import Action

H = "a.lab.test"
VERSION = compute_policy_version(lab_enabled=False, lab_cidr=None)


async def _call(target: str, backend: FakeChainBackend, **view):
    view.setdefault("scope_allow", (H,))
    return await decide_and_record(
        Action(kind="http", target=target, adapter="unit"),
        make_view(policy_version=VERSION, **view),
        NOW,
        resolver=MapResolver({H: ("192.0.2.1",)}),
        clock=FixedClock(NOW),
        rate_limit_store=InMemoryRateLimitStore(),
        chain_backend=backend,
        actor="system",
    )


@pytest.mark.parametrize("exc", [RuntimeError("db down"), asyncio.CancelledError()])
@pytest.mark.parametrize("target", [H, "denied.lab.test"])
async def test_append_failure_propagates_for_allow_and_deny(
    exc: BaseException, target: str
) -> None:
    b = FakeChainBackend()
    b.fail_with = exc
    with pytest.raises(type(exc)):
        await _call(target, b)
    assert b.appended == []


async def test_no_catch_no_retry() -> None:
    attempts = 0

    class Counting(FakeChainBackend):
        async def append(self, *a, **k):  # type: ignore[no-untyped-def,override]
            nonlocal attempts
            attempts += 1
            raise OSError("x")

    with pytest.raises(OSError):
        await _call(H, Counting())
    assert attempts == 1
