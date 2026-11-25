"""Idempotency on the wire (design 12.4, PD-18) and the revoke-memo namespace finding (DE-01)."""
from __future__ import annotations

import time

import pytest
from acc_support import SCAN_PAYLOAD, World, assert_problem, engagement_payload

pytestmark = pytest.mark.acceptance


@pytest.mark.covers_code("IDEMPOTENCY_CONFLICT")
def test_same_key_same_body_replays_and_different_body_conflicts(world: World) -> None:
    a = world.org("admin")
    p = engagement_payload()
    r1 = world.create(a, p, key="idem-a")
    r2 = world.create(a, p, key="idem-a")
    assert r1.status_code == r2.status_code == 201 and r1.json() == r2.json()
    assert "idempotent-replayed" not in r1.headers
    assert r2.headers["idempotent-replayed"] == "true"
    assert r1.headers["x-request-id"] != r2.headers["x-request-id"]
    eid = r1.json()["id"]
    assert len(world.ledger_rows(f"engagement:{eid}")) == 1
    assert world.engagements_of(a.org_id) == 1

    other = engagement_payload()
    assert_problem(world.create(a, other, key="idem-a"), 409, "IDEMPOTENCY_CONFLICT")
    assert world.engagements_of(a.org_id) == 1  # first resource unchanged

    # the same key on a different path is a conflict too
    assert_problem(world.post(f"/v1/engagements/{eid}/scans", a, SCAN_PAYLOAD, key="idem-a"),
                   409, "IDEMPOTENCY_CONFLICT")


def test_no_key_twice_gives_two_resources(world: World) -> None:
    a = world.org("admin")
    p = engagement_payload()
    assert world.create(a, p).json()["id"] != world.create(a, p).json()["id"]
    assert world.engagements_of(a.org_id) == 2


def test_same_key_same_invalid_body_replays_one_intake_entry(world: World) -> None:
    a = world.org("admin")
    p = engagement_payload()
    p["authorization"]["confirmed"] = False
    r1 = world.create(a, p, key="idem-bad")
    r2 = world.create(a, p, key="idem-bad")
    b1 = assert_problem(r1, 422, "AUTH_NOT_CONFIRMED")
    b2 = assert_problem(r2, 422, "AUTH_NOT_CONFIRMED")
    assert b1["ledger_seq"] == b2["ledger_seq"]
    assert {k: v for k, v in b1.items() if k != "request_id"} == {
        k: v for k, v in b2.items() if k != "request_id"}
    assert r2.headers.get("idempotent-replayed") == "true"
    assert len(world.ledger_rows(a.intake)) == 1


def test_key_syntax_is_enforced(world: World) -> None:
    a = world.org("admin")
    for bad in ("", "has space", "k" * 256, "tab\there"):
        try:
            r = world.create(a, key=bad)
        except Exception:  # noqa: BLE001 - the HTTP client may refuse the header itself
            continue
        assert_problem(r, 422, "INVALID_REQUEST")
    assert world.create(a, key="k" * 255).status_code == 201


def test_revoke_retry_after_a_client_key_shaped_like_the_memo_key_still_returns_original(
        world: World) -> None:
    """DE-01. The revoke memo lives in idempotency_keys under
    sha256('idem-v1:<len(org)>:<org>:revoke-record:<engagement id>'), which is exactly the storage
    key a CLIENT gets for ``Idempotency-Key: revoke-record:<engagement id>``. A write-role key can
    therefore occupy the memo row before the revoke. The first revoke still works, but every later
    retry (AC7 point 4: 'second revoke returns the original body') and every repair sees a non-200,
    non-claimable row and ends in a 503 after the claim wait."""
    a = world.org("assessor")
    eid = world.create(a).json()["id"]
    squat = world.create(a, key=f"revoke-record:{eid}")  # stores a 201 under the memo key
    assert squat.status_code == 201
    first = world.post(f"/v1/engagements/{eid}/revoke", a, {"reason": "t"})
    assert first.status_code == 200
    t0 = time.monotonic()
    again = world.post(f"/v1/engagements/{eid}/revoke", a, {"reason": "t2"})
    assert again.status_code == 200 and again.json() == first.json()
    assert time.monotonic() - t0 < 3.0  # never a 10 s wait followed by a 503


def test_revoke_with_the_same_idempotency_key_as_create_is_a_conflict(world: World) -> None:
    """DE-02. Design 12.4 / PD-18: 'same key on revoke vs create path gives 409'. The revoke
    handler never reads Idempotency-Key, so the header is silently ignored."""
    a = world.org("admin")
    eid = world.create(a, key="k-create-revoke").json()["id"]
    r = world.post(f"/v1/engagements/{eid}/revoke", a, {"reason": "t"}, key="k-create-revoke")
    assert_problem(r, 409, "IDEMPOTENCY_CONFLICT")
