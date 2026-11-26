"""AC7 (design 12.4, PD-18): revoke makes later scan creation fail with REVOKED and is a ledger
entry. ledger_seq values: create 0, revoke 1, REVOKED decision 2."""
from __future__ import annotations

import pytest
from acc_support import SCAN_PAYLOAD, World, assert_problem

pytestmark = pytest.mark.acceptance


@pytest.mark.covers_code("REVOKED", "FORBIDDEN_ROLE")
def test_ac7_create_revoke_scan_revoke_again(world: World) -> None:
    admin = world.org("admin")
    viewer = world.key(admin.org_id, "viewer")

    # (1) create
    r = world.create(admin, key="ac7-create-1")
    assert r.status_code == 201
    created = r.json()
    assert set(created) == {"id", "status", "created_at", "ledger_seq"}
    assert created["status"] == "active" and created["ledger_seq"] == 0
    eid = created["id"]
    chain = f"engagement:{eid}"
    v = world.verify(admin, chain)
    assert v.status_code == 200
    assert v.json() == {"result": "ok", "first_bad_seq": None, "records": 1,
                        "checkpoint_seq": None}

    # (2) a queued scan, then revoke
    sid = world.seed_scan(admin, eid, "queued")
    rv = world.post(f"/v1/engagements/{eid}/revoke", admin, {"reason": "test"})
    assert rv.status_code == 200
    body = rv.json()
    assert set(body) == {"status", "revoked_at", "ledger_seq"}
    assert body["status"] == "revoked" and body["ledger_seq"] == 1
    assert world.sql("SELECT status FROM scans WHERE id = :s", s=sid)[0]["status"] == "cancelled"
    assert world.get(f"/v1/engagements/{eid}", admin).json()["status"] == "revoked"

    # (3) scan creation after revoke
    sc = world.post(f"/v1/engagements/{eid}/scans", admin, SCAN_PAYLOAD)
    p = assert_problem(sc, 409, "REVOKED")
    assert p["ledger_seq"] == 2
    vv = world.verify(admin, chain).json()
    assert vv["result"] == "ok" and vv["records"] == 3

    # the decision entry itself (channel 3)
    rows = world.ledger_rows(chain)
    assert [x["seq"] for x in rows] == [0, 1, 2]
    assert rows[0]["kind"] == "engagement.created"
    assert rows[1]["kind"] == "engagement.revoked"
    assert rows[2]["kind"] == "policy.decision"
    assert rows[2]["payload"]["rule_id"] == "REVOKED" and rows[2]["payload"]["allowed"] is False
    assert rows[2]["actor"] == f"user:{admin.key_id}"

    # (4) second revoke: original body, nothing written; exactly one engagement.revoked entry
    again = world.post(f"/v1/engagements/{eid}/revoke", admin, {"reason": "other reason"})
    assert again.status_code == 200 and again.json() == body
    assert world.verify(admin, chain).json()["records"] == 3
    assert sum(1 for x in world.ledger_rows(chain) if x["kind"] == "engagement.revoked") == 1

    # (5) viewer cannot revoke
    assert_problem(world.post(f"/v1/engagements/{eid}/revoke", viewer, {"reason": "x"}),
                   403, "FORBIDDEN_ROLE")
    # a viewer may read
    assert world.get(f"/v1/engagements/{eid}", viewer).status_code == 200


def test_ac7_revoke_payload_has_hashes_never_the_reason(world: World) -> None:
    admin = world.org("admin")
    eid = world.create(admin).json()["id"]
    reason = "customer asked: ticket 4411 canary-reason"
    assert world.post(f"/v1/engagements/{eid}/revoke", admin, {"reason": reason}
                      ).status_code == 200
    row = [x for x in world.ledger_rows(f"engagement:{eid}") if x["kind"] == "engagement.revoked"]
    assert len(row) == 1
    assert "canary-reason" not in str(row[0]["payload"])
    assert row[0]["payload"].get("reason_len") == len(reason)
    assert row[0]["payload"].get("revoked_by") == admin.key_id


def test_ac7_scan_after_revoke_cancels_nothing_and_inserts_no_scan(world: World) -> None:
    admin = world.org("admin")
    eid = world.create(admin).json()["id"]
    world.post(f"/v1/engagements/{eid}/revoke", admin, {"reason": "t"})
    before = world.count("SELECT count(*) AS n FROM scans WHERE engagement_id = :e", e=eid)
    for _ in range(3):
        assert world.post(f"/v1/engagements/{eid}/scans", admin, SCAN_PAYLOAD
                          ).status_code == 409
    assert world.count("SELECT count(*) AS n FROM scans WHERE engagement_id = :e", e=eid) == before


def test_ac7_replayed_revoked_scan_response_is_terminal_replay(world: World) -> None:
    """REVOKED is a stored terminal outcome (ADR-0006 decision 5): same key twice = a replay."""
    admin = world.org("admin")
    eid = world.create(admin).json()["id"]
    world.post(f"/v1/engagements/{eid}/revoke", admin, {"reason": "t"})
    first = world.post(f"/v1/engagements/{eid}/scans", admin, SCAN_PAYLOAD, key="rv-1")
    second = world.post(f"/v1/engagements/{eid}/scans", admin, SCAN_PAYLOAD, key="rv-1")
    assert first.status_code == second.status_code == 409
    assert "idempotent-replayed" not in first.headers
    assert second.headers.get("idempotent-replayed") == "true"
    assert first.json()["ledger_seq"] == second.json()["ledger_seq"]
    decisions = [x for x in world.ledger_rows(f"engagement:{eid}") if x["kind"] == "policy.decision"]
    assert len(decisions) == 1
