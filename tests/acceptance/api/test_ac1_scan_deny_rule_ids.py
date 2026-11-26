"""AC1, API half (PD-18): deny decisions on scan creation are ledger entries with the right rule_id.
Engagement rows are seeded by ORM (bypassing creation) so the gate runs without DNS. The rule ids
are read through channel 3 (the app-role connection), because verify returns counts only."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from acc_support import SCAN_PAYLOAD, World, assert_problem

pytestmark = pytest.mark.acceptance


def _decisions(world: World, eid: str) -> list[dict[str, Any]]:
    return [r for r in world.ledger_rows(f"engagement:{eid}") if r["kind"] == "policy.decision"]


def _check(world: World, actor: Any, eid: str, status: int, code: str, rule: str) -> dict[str, Any]:
    before = len(world.ledger_rows(f"engagement:{eid}"))
    resp = world.post(f"/v1/engagements/{eid}/scans", actor, SCAN_PAYLOAD)
    body = assert_problem(resp, status, code)
    rows = world.ledger_rows(f"engagement:{eid}")
    row = next(r for r in rows if r["seq"] == body["ledger_seq"])
    assert row["kind"] == "policy.decision"
    assert row["payload"]["rule_id"] == rule and row["payload"]["allowed"] is False
    assert row["actor"] == f"user:{actor.key_id}"
    assert len(rows) >= before + 1
    assert world.count("SELECT count(*) AS n FROM scans WHERE engagement_id = :e", e=eid) == 0
    return body


@pytest.mark.covers_code("REVOKED")
def test_a_revoked(world: World) -> None:
    a = world.org("admin")
    eid = world.seed_engagement(a, status="revoked")
    _check(world, a, eid, 409, "REVOKED", "REVOKED")


@pytest.mark.covers_code("EXPIRED")
def test_b_expired(world: World) -> None:
    a = world.org("admin")
    now = datetime.now(UTC)
    eid = world.seed_engagement(a, not_before=now - timedelta(days=2),
                                not_after=now - timedelta(days=1))
    _check(world, a, eid, 409, "EXPIRED", "EXPIRED")


@pytest.mark.covers_code("TARGET_DENIED")
def test_c_excluded(world: World) -> None:
    a = world.org("admin")
    eid = world.seed_engagement(a, deny=["target.lab.test"])
    _check(world, a, eid, 422, "TARGET_DENIED", "EXCLUDED")


@pytest.mark.covers_code("TARGET_NOT_IN_SCOPE")
def test_d_out_of_scope(world: World) -> None:
    a = world.org("admin")
    eid = world.seed_engagement(a, allow=["something-else.lab.test"])
    _check(world, a, eid, 422, "TARGET_NOT_IN_SCOPE", "OUT_OF_SCOPE")


@pytest.mark.covers_code("TARGET_DENIED")
def test_e_always_deny_list(world: World) -> None:
    a = world.org("admin")
    eid = world.seed_engagement(a, domains=["169.254.169.254"], allow=["169.254.169.254"])
    _check(world, a, eid, 422, "TARGET_DENIED", "DENY_ALWAYS_LIST")


@pytest.mark.covers_code("TARGET_NOT_IN_SCOPE")
def test_f_private_literal_in_lab_profile_is_out_of_scope(world: World) -> None:
    a = world.org("admin")
    eid = world.seed_engagement(a, domains=["10.0.0.5"], allow=["10.0.0.5"], profile="lab")
    _check(world, a, eid, 422, "TARGET_NOT_IN_SCOPE", "OUT_OF_SCOPE")


@pytest.mark.covers_code("TARGET_DENIED")
def test_g_not_yet_valid_is_409_target_denied(world: World) -> None:
    a = world.org("admin")
    now = datetime.now(UTC)
    eid = world.seed_engagement(a, not_before=now + timedelta(days=1),
                                not_after=now + timedelta(days=2))
    _check(world, a, eid, 409, "TARGET_DENIED", "NOT_YET_VALID")


def test_h_replay_rules(world: World) -> None:
    """(h) after (a): the same key twice is a replay (REVOKED is terminal), one decision entry.
    After (c): the second request is NOT a replay and writes a second decision entry."""
    a = world.org("admin")
    revoked = world.seed_engagement(a, status="revoked")
    r1 = world.post(f"/v1/engagements/{revoked}/scans", a, SCAN_PAYLOAD, key="h-key-1")
    r2 = world.post(f"/v1/engagements/{revoked}/scans", a, SCAN_PAYLOAD, key="h-key-1")
    assert r1.status_code == r2.status_code == 409
    assert "idempotent-replayed" not in r1.headers and r2.headers["idempotent-replayed"] == "true"
    assert len(_decisions(world, revoked)) == 1

    excluded = world.seed_engagement(a, deny=["target.lab.test"])
    c1 = world.post(f"/v1/engagements/{excluded}/scans", a, SCAN_PAYLOAD, key="h-key-2")
    c2 = world.post(f"/v1/engagements/{excluded}/scans", a, SCAN_PAYLOAD, key="h-key-2")
    assert c1.status_code == c2.status_code == 422
    assert "idempotent-replayed" not in c2.headers
    assert len(_decisions(world, excluded)) == 2


def test_scan_request_edges_never_reach_the_gate(world: World) -> None:
    """PD-21: write_tests must be literal false, schedule null, stages a proper subset: 422
    INVALID_REQUEST and ZERO ledger entries on the engagement chain beyond creation."""
    a = world.org("admin")
    eid = world.create(a).json()["id"]
    base = len(world.ledger_rows(f"engagement:{eid}"))
    bad: list[Any] = [
        {**SCAN_PAYLOAD, "options": {"write_tests": True}},
        {**SCAN_PAYLOAD, "options": {"write_tests": "false"}},
        {**SCAN_PAYLOAD, "options": {"write_tests": 0}},
        {**SCAN_PAYLOAD, "schedule": {"cron": "* * * * *"}},
        {**SCAN_PAYLOAD, "stages": []},
        {**SCAN_PAYLOAD, "stages": ["discover", "discover"]},
        {**SCAN_PAYLOAD, "stages": ["exploit"]},
        {**SCAN_PAYLOAD, "extra": 1},
    ]
    for body in bad:
        assert_problem(world.post(f"/v1/engagements/{eid}/scans", a, body), 422,
                       "INVALID_REQUEST")
    assert len(world.ledger_rows(f"engagement:{eid}")) == base
    assert world.count("SELECT count(*) AS n FROM scans WHERE engagement_id = :e", e=eid) == 0
