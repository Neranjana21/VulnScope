"""Actor validation and version binding (SEC-A9, RC8) in decide_and_record.

DEPENDS ON Task B (`ledger.canonical`) through decide_and_record's import.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from policy_test_support import NOW, FakeChainBackend, FixedClock, MapResolver, make_view

from vulnscope.policy.decide_and_record import decide_and_record
from vulnscope.policy.denylist import compute_policy_version
from vulnscope.policy.ratelimit import InMemoryRateLimitStore
from vulnscope.policy.types import Action, RuleId

H = "a.lab.test"


async def _call(
    backend,
    *,
    actor="system",
    version=None,
    lab_enabled=False,
    lab_cidr=None,
    target=H,
    clock=None,
    **view,
):
    version = version or compute_policy_version(lab_enabled=lab_enabled, lab_cidr=lab_cidr)
    return await decide_and_record(
        Action(kind="http", target=target, adapter="unit"),
        make_view(policy_version=version, scope_allow=(H, "127.0.0.1"), **view),
        NOW,
        resolver=MapResolver({H: ("192.0.2.1",)}),
        clock=clock or FixedClock(NOW),
        rate_limit_store=InMemoryRateLimitStore(),
        chain_backend=backend,
        actor=actor,
        lab_enabled=lab_enabled,
        lab_cidr=lab_cidr,
    )


@pytest.mark.parametrize("actor", ["system", "user:42", "user:a-b_C", "user:" + "x" * 64])
async def test_good_actors(actor: str) -> None:
    b = FakeChainBackend()
    await _call(b, actor=actor)
    assert b.appended[0].actor == actor


@pytest.mark.parametrize(
    "actor",
    [
        "",
        "root",
        "user:",
        "user:" + "x" * 65,
        "user:a:b",
        "System",
        "user:a b",
        "user:\n",
        "service:x",
    ],
)
async def test_bad_actor_raises_before_anything_runs(actor: str) -> None:
    b = FakeChainBackend()
    with pytest.raises(ValueError):
        await _call(b, actor=actor)
    assert b.appended == [] and b.head_calls == 0


async def test_version_mismatch_raises_before_anything_runs() -> None:
    b = FakeChainBackend()
    with pytest.raises(ValueError):
        await _call(b, version="1.0.0+teststub")
    assert b.appended == [] and b.head_calls == 0


async def test_payload_records_lab_inputs() -> None:
    b = FakeChainBackend()
    await _call(b, lab_enabled=True, lab_cidr="10.20.0.0/16", profile="lab", target="127.0.0.1")
    p = b.appended[0].payload
    assert p["lab_enabled"] is True and p["lab_cidr"] == "10.20.0.0/16"


async def test_garbage_lab_cidr_is_a_recorded_deny_not_a_raise() -> None:
    b = FakeChainBackend()
    d = await _call(b, lab_enabled=True, lab_cidr="garbage")
    assert d.rule_id == RuleId.OUT_OF_SCOPE and d.reason == "invalid lab configuration"
    assert len(b.appended) == 1
    assert b.appended[0].payload["lab_cidr"] == "garbage"


async def test_garbage_lab_cidr_with_lab_disabled_does_not_raise() -> None:
    b = FakeChainBackend()
    d = await decide_and_record(
        Action(kind="http", target=H, adapter="unit"),
        make_view(
            policy_version=compute_policy_version(lab_enabled=False, lab_cidr=None),
            scope_allow=(H,),
        ),
        NOW,
        resolver=MapResolver({H: ("192.0.2.1",)}),
        clock=FixedClock(NOW),
        rate_limit_store=InMemoryRateLimitStore(),
        chain_backend=b,
        actor="system",
        lab_enabled=False,
        lab_cidr="garbage",
    )
    assert d.allowed and b.appended[0].payload["lab_cidr"] is None


async def test_skew_boundary_60_seconds() -> None:
    await _call(FakeChainBackend(), clock=FixedClock(NOW - timedelta(seconds=59)))
    with pytest.raises(ValueError):
        await _call(FakeChainBackend(), clock=FixedClock(NOW - timedelta(seconds=61)))


async def test_naive_now_raises_and_writes_nothing() -> None:
    b = FakeChainBackend()
    with pytest.raises(ValueError):
        await decide_and_record(
            Action(kind="http", target=H, adapter="unit"),
            make_view(
                policy_version=compute_policy_version(lab_enabled=False, lab_cidr=None),
                scope_allow=(H,),
            ),
            NOW.replace(tzinfo=None),
            resolver=MapResolver({H: ("192.0.2.1",)}),
            clock=FixedClock(NOW),
            rate_limit_store=InMemoryRateLimitStore(),
            chain_backend=b,
            actor="system",
        )
    assert b.appended == []
