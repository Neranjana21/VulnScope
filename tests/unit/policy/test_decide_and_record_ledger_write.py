"""AC1 ledger half: exactly one append per call, allow AND deny (fake backend).

DEPENDS ON Task B (`vulnscope.ledger.canonical.sanitize_payload`): until that is
merged these tests cannot even import `decide_and_record`.
"""

from __future__ import annotations

import json
from datetime import timedelta

import pytest
from policy_test_support import NOW, FakeChainBackend, FixedClock, MapResolver, make_view

from vulnscope.policy.decide_and_record import decide_and_record, policy_decision_to_payload
from vulnscope.policy.denylist import compute_policy_version
from vulnscope.policy.ratelimit import InMemoryRateLimitStore
from vulnscope.policy.types import Action, AuthorizationBasis, RuleId

H = "a.lab.test"
TABLE = {H: ("192.0.2.1",)}
VERSION = compute_policy_version(lab_enabled=False, lab_cidr=None)


async def _call(
    target: str,
    backend: FakeChainBackend,
    *,
    now=NOW,
    clock=None,
    actor="system",
    resolver=None,
    **view,
):
    view.setdefault("scope_allow", (H,))
    view.setdefault("policy_version", VERSION)
    return await decide_and_record(
        Action(kind="http", target=target, adapter="unit"),
        make_view(**view),
        now,
        resolver=resolver or MapResolver(TABLE),
        clock=clock or FixedClock(now),
        rate_limit_store=InMemoryRateLimitStore(),
        chain_backend=backend,
        actor=actor,
    )


async def test_allow_writes_one_entry() -> None:
    b = FakeChainBackend()
    d = await _call(H, b)
    assert d.allowed and d.ledger_seq == 0
    (e,) = b.appended
    assert e.kind == "policy.decision"
    assert e.chain_id == "engagement:11111111-1111-7111-8111-111111111111"
    assert e.actor == "system"
    assert e.ts == NOW
    assert dict(e.payload) == policy_decision_to_payload(d)
    json.dumps(dict(e.payload), allow_nan=False)


@pytest.mark.parametrize(
    ("target", "view", "rule"),
    [
        ("other.lab.test", {}, RuleId.OUT_OF_SCOPE),
        (H, {"status": "revoked"}, RuleId.REVOKED),
        ("169.254.169.254", {"scope_allow": ("0.0.0.0/0",)}, RuleId.DENY_ALWAYS_LIST),
        ("metadata", {}, RuleId.DENY_ALWAYS_LIST),
        ("a b", {}, RuleId.OUT_OF_SCOPE),
    ],
)
async def test_every_deny_is_recorded(target: str, view: dict, rule: RuleId) -> None:
    b = FakeChainBackend()
    d = await _call(target, b, **view)
    assert not d.allowed and d.rule_id == rule
    assert len(b.appended) == 1 and d.ledger_seq == 0
    assert b.appended[0].payload["allowed"] is False
    assert b.appended[0].payload["rule_id"] == rule.value


async def test_payload_shape_and_plain_types() -> None:
    b = FakeChainBackend()
    basis = AuthorizationBasis(True, "user:7", "b" * 64)
    d = await _call(H, b, authorization_basis=basis)
    p = dict(b.appended[0].payload)
    assert p["schema_version"] == 1
    assert p["policy_version"] == VERSION and p["rule_id"] == "ALLOW"
    assert p["lab_enabled"] is False and p["lab_cidr"] is None
    assert p["action"] == {
        "kind": "http",
        "target": H,
        "resolved_ips": ["192.0.2.1"],
        "adapter": "unit",
        "is_redirect_hop": False,
    }
    assert p["ts"] == "2026-01-15T00:00:00Z"
    assert p["authorization_basis"] == {
        "confirmed": True,
        "approver": "user:7",
        "statement_sha256": "b" * 64,
    }
    assert "clock_ts" not in p
    assert d.ledger_seq == 0

    b2 = FakeChainBackend()
    await _call(H, b2)
    assert b2.appended[0].payload["authorization_basis"] is None


async def test_hostile_target_is_recorded_once_and_flagged() -> None:
    b = FakeChainBackend()
    d = await _call("a\x00b\ud800" + "x" * 5000, b)
    assert not d.allowed and len(b.appended) == 1
    assert b.appended[0].payload.get("sanitized") is True
    assert "\x00" not in json.dumps(dict(b.appended[0].payload))


async def test_skew_recorded_when_over_one_second_and_rejected_over_sixty() -> None:
    b = FakeChainBackend()
    await _call(H, b, clock=FixedClock(NOW + timedelta(seconds=30)))
    assert "clock_ts" in b.appended[0].payload
    b2 = FakeChainBackend()
    await _call(H, b2, clock=FixedClock(NOW + timedelta(milliseconds=500)))
    assert "clock_ts" not in b2.appended[0].payload
    b3 = FakeChainBackend()
    with pytest.raises(ValueError):
        await _call(H, b3, clock=FixedClock(NOW + timedelta(seconds=61)))
    assert b3.appended == []
    await _call(H, FakeChainBackend(), clock=FixedClock(NOW + timedelta(seconds=59)))


async def test_chain_id_is_always_the_engagements_own() -> None:
    b = FakeChainBackend()
    await _call(H, b, engagement_id="eng-9")
    assert b.appended[0].chain_id == "engagement:eng-9"
