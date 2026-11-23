"""SEC-A7 / SEC-A18 / RC6: event-loop safety, head preflight, cancellation residual.

DEPENDS ON Task B (`ledger.canonical`) through decide_and_record's import.
"""

from __future__ import annotations

import asyncio
import threading
import time

import pytest
from policy_test_support import NOW, FakeChainBackend, FixedClock, MapResolver, make_view

from vulnscope.policy.decide_and_record import decide_and_record
from vulnscope.policy.denylist import compute_policy_version
from vulnscope.policy.ratelimit import InMemoryRateLimitStore
from vulnscope.policy.resolver import ResolutionError
from vulnscope.policy.types import Action, RuleId

H = "a.lab.test"
VERSION = compute_policy_version(lab_enabled=False, lab_cidr=None)


def _kw(resolver, backend):
    return dict(
        resolver=resolver,
        clock=FixedClock(NOW),
        rate_limit_store=InMemoryRateLimitStore(),
        chain_backend=backend,
        actor="system",
    )


class SleepyResolver:
    def __init__(self, delay: float, *, fail: bool = False) -> None:
        self.delay, self.fail, self.calls = delay, fail, []

    def resolve(self, hostname: str) -> tuple[str, ...]:
        self.calls.append(hostname)
        time.sleep(self.delay)
        if self.fail:
            raise ResolutionError("timeout")
        return ("192.0.2.1",)


async def test_event_loop_keeps_ticking_during_slow_resolution() -> None:
    ticks = 0
    stop = False

    async def ticker() -> None:
        nonlocal ticks
        while not stop:
            await asyncio.sleep(0)
            ticks += 1

    task = asyncio.create_task(ticker())
    resolver = SleepyResolver(0.2)
    d = await decide_and_record(
        Action("http", H, "unit"),
        make_view(policy_version=VERSION, scope_allow=(H,)),
        NOW,
        **_kw(resolver, FakeChainBackend()),
    )
    stop = True
    await task
    assert d.allowed and ticks > 20


async def test_resolver_timeout_is_a_recorded_resolution_failed() -> None:
    b = FakeChainBackend()
    d = await decide_and_record(
        Action("http", H, "unit"),
        make_view(policy_version=VERSION, scope_allow=(H,)),
        NOW,
        **_kw(SleepyResolver(0.01, fail=True), b),
    )
    assert d.rule_id == RuleId.RESOLUTION_FAILED and len(b.appended) == 1


async def test_failing_head_means_no_lookup_and_no_token() -> None:
    b = FakeChainBackend()
    b.head_fail_with = RuntimeError("ledger down")
    resolver = MapResolver({H: ("192.0.2.1",)})
    store = InMemoryRateLimitStore()
    with pytest.raises(RuntimeError):
        await decide_and_record(
            Action("http", H, "unit"),
            make_view(policy_version=VERSION, scope_allow=(H,), rate_limit_rps=1.0),
            NOW,
            resolver=resolver,
            clock=FixedClock(NOW),
            rate_limit_store=store,
            chain_backend=b,
            actor="system",
        )
    assert resolver.calls == [] and b.appended == []
    assert store.key_count() == 0


async def test_cancellation_mid_resolution_documented_residual() -> None:
    started, release = threading.Event(), threading.Event()
    calls: list[str] = []

    class Blocking:
        def resolve(self, hostname: str) -> tuple[str, ...]:
            calls.append(hostname)
            started.set()
            release.wait(5)
            return ("192.0.2.1",)

    b = FakeChainBackend()
    task = asyncio.create_task(
        decide_and_record(
            Action("http", H, "unit"),
            make_view(policy_version=VERSION, scope_allow=(H,)),
            NOW,
            **_kw(Blocking(), b),
        )
    )
    while not started.is_set():
        await asyncio.sleep(0.005)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert b.appended == [] and calls == [H]
    release.set()
    await asyncio.sleep(0.05)  # worker thread finishes; no record is written
    assert b.appended == []
