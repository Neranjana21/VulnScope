"""AC7 and the revoke recorder (design 6, PD-06, PD-07, N-02, N-05, A's binding items)."""
from __future__ import annotations

import asyncio
from datetime import timedelta
from typing import Any

import pytest
from api_it_support import Env, TestOrg, make_env
from api_payloads import SCAN_PAYLOAD

from vulnscope.api.limits import Timeouts

pytestmark = pytest.mark.integration


def revoked_entries(env: Env, eid: str) -> list[Any]:
    return env.chain.entries(f"engagement:{eid}", "engagement.revoked")


async def revoke(env: Env, org: TestOrg, eid: str, reason: str = "test"):  # type: ignore[no-untyped-def]
    return await env.post(f"/v1/engagements/{eid}/revoke", org, {"reason": reason})


async def test_ac7_full_flow(env: Env) -> None:
    org = await env.org()
    created = (await env.create_engagement(org)).json()
    eid = created["id"]
    assert created["ledger_seq"] == 0
    sid = await env.seed_scan(org, eid, "queued")
    r = await revoke(env, org, eid)
    assert r.status_code == 200
    body = r.json()
    assert set(body) == {"status", "revoked_at", "ledger_seq"}
    assert body["status"] == "revoked" and body["ledger_seq"] == 1
    row = await env.sql("SELECT status FROM scans WHERE id=:s", s=sid)
    assert row[0]["status"] == "cancelled"
    assert (await env.get(f"/v1/engagements/{eid}", org)).json()["status"] == "revoked"
    s = await env.post(f"/v1/engagements/{eid}/scans", org, SCAN_PAYLOAD)
    assert s.status_code == 409 and s.json()["code"] == "REVOKED" and s.json()["ledger_seq"] == 2
    dec = env.chain.entries(f"engagement:{eid}")[2]
    assert dec.kind == "policy.decision" and dec.payload["rule_id"] == "REVOKED"
    assert dec.payload["allowed"] is False and dec.actor == f"user:{org.key_id}"
    again = await revoke(env, org, eid, "other reason")
    assert again.status_code == 200 and again.json() == body
    assert len(env.chain.entries(f"engagement:{eid}")) == 3
    assert len(revoked_entries(env, eid)) == 1
    n = (await env.sql("SELECT count(*) AS n FROM scans WHERE engagement_id=:e AND status IN "
                       "('pending','queued','running')", e=eid))[0]["n"]
    assert n == 0


async def test_revoke_payload_has_hashes_not_the_reason(env: Env) -> None:
    org = await env.org()
    eid = (await env.create_engagement(org)).json()["id"]
    await revoke(env, org, eid, "customer asked: ticket 4411")
    (e,) = revoked_entries(env, eid)
    pl = dict(e.payload)
    assert "ticket 4411" not in str(pl)
    assert pl["reason_len"] == len("customer asked: ticket 4411") and len(pl["reason_sha256"]) == 64
    assert pl["revoked_by"] == org.key_id and pl["repaired"] is False
    assert set(pl) == {"schema_version", "engagement_id", "revoked_at", "reason_sha256",
                       "reason_len", "revoked_by", "repaired"}


async def test_revoke_reason_validation(env: Env) -> None:
    org = await env.org()
    eid = (await env.create_engagement(org)).json()["id"]
    assert (await revoke(env, org, eid, "")).status_code == 422
    assert (await revoke(env, org, eid, "r" * 1025)).status_code == 422
    r = await revoke(env, org, eid, "password=hunter2xx")
    assert r.status_code == 422 and r.json()["code"] == "SECRET_INLINE"
    assert "ledger_seq" not in r.json()
    assert (await env.post(f"/v1/engagements/{eid}/revoke", org, {"reason": "x", "z": 1})
            ).status_code == 422
    assert (await env.get(f"/v1/engagements/{eid}", org)).json()["status"] == "active"
    assert (await revoke(env, org, eid, "r" * 1024)).status_code == 200


async def test_revoke_concurrency_records_exactly_one_entry(env: Env) -> None:
    org = await env.org()
    eid = (await env.create_engagement(org)).json()["id"]
    rs = await asyncio.gather(*[revoke(env, org, eid) for _ in range(30)])
    assert [r.status_code for r in rs] == [200] * 30
    assert len({(r.json()["revoked_at"], r.json()["ledger_seq"]) for r in rs}) == 1
    assert len(revoked_entries(env, eid)) == 1
    assert len(env.chain.entries(f"engagement:{eid}")) == 2


async def test_revoke_with_one_append_failure_still_exactly_one_entry(env: Env) -> None:
    org = await env.org()
    eid = (await env.create_engagement(org)).json()["id"]
    env.chain.fail_next_appends = 1
    rs = await asyncio.gather(*[revoke(env, org, eid) for _ in range(10)])
    codes = sorted(r.status_code for r in rs)
    assert codes == [200] * 9 + [503]
    assert len({r.json()["ledger_seq"] for r in rs if r.status_code == 200}) == 1
    assert len(revoked_entries(env, eid)) == 1
    assert "canary-should-never-surface" not in "".join(r.text for r in rs)


async def test_revoke_with_failing_ledger_is_503_and_stays_revoked_then_repairs(env: Env) -> None:
    org = await env.org()
    eid = (await env.create_engagement(org)).json()["id"]
    env.chain.fail_always = True
    rs = await asyncio.gather(*[revoke(env, org, eid) for _ in range(5)])
    assert [r.status_code for r in rs] == [503] * 5
    assert revoked_entries(env, eid) == []
    assert (await env.get(f"/v1/engagements/{eid}", org)).json()["status"] == "revoked"
    env.chain.fail_always = False
    r = await revoke(env, org, eid)
    assert r.status_code == 200 and len(revoked_entries(env, eid)) == 1
    assert dict(revoked_entries(env, eid)[0].payload)["repaired"] is True


async def test_repair_without_a_client_retry_via_scan_attempt(env: Env) -> None:
    org = await env.org()
    eid = (await env.create_engagement(org)).json()["id"]
    env.chain.fail_next_appends = 1
    assert (await revoke(env, org, eid)).status_code == 503
    assert revoked_entries(env, eid) == []
    r = await env.post(f"/v1/engagements/{eid}/scans", org, SCAN_PAYLOAD)
    assert r.status_code == 409 and r.json()["code"] == "REVOKED"
    assert len(revoked_entries(env, eid)) == 1


async def test_get_engagement_never_writes_to_the_ledger(env: Env) -> None:
    org = await env.org()
    eid = await env.seed_engagement(org, status="revoked")
    n = env.chain.count("append")
    assert (await env.get(f"/v1/engagements/{eid}", org)).status_code == 200
    assert env.chain.count("append") == n


async def test_revoke_attribution_survives_a_failed_append_and_other_repairer(env: Env) -> None:
    a = await env.org()
    b = await env.key(a.org_id, "assessor")
    eid = (await env.create_engagement(a)).json()["id"]
    env.chain.fail_next_appends = 1
    assert (await revoke(env, a, eid)).status_code == 503
    assert (await revoke(env, b, eid)).status_code == 200
    (e,) = revoked_entries(env, eid)
    assert dict(e.payload)["revoked_by"] == a.key_id
    assert e.actor == f"user:{b.key_id}" and dict(e.payload)["repaired"] is True


async def test_revoke_of_an_already_revoked_row_without_memo_records_unknown(env: Env) -> None:
    org = await env.org()
    eid = await env.seed_engagement(org, status="revoked")
    r = await revoke(env, org, eid)
    assert r.status_code == 200
    (e,) = revoked_entries(env, eid)
    assert dict(e.payload)["revoked_by"] == "unknown" and dict(e.payload)["repaired"] is True


async def test_revoke_records_on_an_oversized_chain(env: Env) -> None:
    org = await env.org()
    eid = await env.seed_engagement(org, status="revoked")
    env.chain.prefill(f"engagement:{eid}", 20_001)
    r = await revoke(env, org, eid)
    assert r.status_code == 200 and len(revoked_entries(env, eid)) == 1
    n = len(env.chain.entries(f"engagement:{eid}"))
    r2 = await revoke(env, org, eid)  # memo present: nothing appended
    assert r2.status_code == 200 and r2.json()["ledger_seq"] == r.json()["ledger_seq"]
    assert len(env.chain.entries(f"engagement:{eid}")) == n


async def test_revoke_search_budget_expiry_still_appends(api_db: Any) -> None:
    e = await make_env(api_db, timeouts=Timeouts(claim_poll_s=0.01, revoke_search_budget_s=0.05))
    try:
        org = await e.org()
        eid = await e.seed_engagement(org, status="revoked")
        e.chain.prefill(f"engagement:{eid}", 500)
        e.chain.read_delay = 0.01
        r = await revoke(e, org, eid)
        assert r.status_code == 200 and len(revoked_entries(e, eid)) == 1
    finally:
        await e.close()


async def test_existing_entry_is_found_not_duplicated(env: Env) -> None:
    org = await env.org()
    eid = await env.seed_engagement(org, status="revoked")
    await env.chain.append(f"engagement:{eid}", "engagement.revoked", "system",
                           {"engagement_id": eid}, env.clock.now())
    r = await revoke(env, org, eid)
    assert r.status_code == 200 and r.json()["ledger_seq"] == 0
    assert len(revoked_entries(env, eid)) == 1


async def test_stale_claim_is_taken_over_once_and_a_fresh_one_is_not(api_db: Any) -> None:
    e = await make_env(api_db, timeouts=Timeouts(claim_poll_s=0.01, claim_wait_s=0.3))
    try:
        from vulnscope.api.revoke_recorder import memo_key

        org = await e.org()
        eid = await e.seed_engagement(org, status="revoked")
        key = memo_key(org.org_id, eid)
        await e.exec(
            "INSERT INTO idempotency_keys (key, org_id, request_hash, response_body,"
            " response_status, created_at) VALUES (:k,:o,'x','{\"revoked_by\":\"someone\"}',0,:t)",
            k=key, o=org.org_id, t=e.clock.now())
        r = await revoke(e, org, eid)
        assert r.status_code == 503 and revoked_entries(e, eid) == []  # fresh claim: not stolen
        e.clock.advance(seconds=121)
        rs = await asyncio.gather(*[revoke(e, org, eid) for _ in range(5)])
        assert [x.status_code for x in rs] == [200] * 5
        assert len(revoked_entries(e, eid)) == 1
        assert dict(revoked_entries(e, eid)[0].payload)["revoked_by"] == "someone"
    finally:
        await e.close()


async def test_corrupt_memo_is_discarded_and_re_recorded(env: Env) -> None:
    from vulnscope.api.revoke_recorder import memo_key

    org = await env.org()
    eid = await env.seed_engagement(org, status="revoked")
    await env.exec(
        "INSERT INTO idempotency_keys (key, org_id, request_hash, response_body,"
        " response_status, created_at) VALUES (:k,:o,'x','{\"seq\": 5}',200,:t)",
        k=memo_key(org.org_id, eid), o=org.org_id, t=env.clock.now())
    r = await revoke(env, org, eid)
    assert r.status_code == 200 and len(revoked_entries(env, eid)) == 1
    assert r.json()["ledger_seq"] == 0


async def test_revoke_flips_the_decision_without_restart(env: Env) -> None:
    org = await env.org()
    eid = (await env.create_engagement(org)).json()["id"]
    assert (await env.post(f"/v1/engagements/{eid}/scans", org, SCAN_PAYLOAD)).status_code == 202
    assert (await revoke(env, org, eid)).status_code == 200
    r = await env.post(f"/v1/engagements/{eid}/scans", org, SCAN_PAYLOAD)
    assert r.status_code == 409 and r.json()["code"] == "REVOKED"


async def test_revoke_vs_scan_race_leaves_no_live_scan(env: Env) -> None:
    for _ in range(5):
        org = await env.org()
        eid = (await env.create_engagement(org)).json()["id"]
        rs = await asyncio.gather(
            *[env.post(f"/v1/engagements/{eid}/scans", org, SCAN_PAYLOAD) for _ in range(6)],
            revoke(env, org, eid))
        assert rs[-1].status_code == 200
        live = (await env.sql(
            "SELECT count(*) AS n FROM scans WHERE engagement_id=:e AND status IN "
            "('pending','queued','running')", e=eid))[0]["n"]
        assert live == 0
        assert all(r.status_code in (202, 409) for r in rs[:-1])


async def test_reconciliation_covers_seven_days_and_attributes_system(env: Env) -> None:
    from vulnscope.api.revoke_recorder import reconcile_revokes

    org = await env.org()
    recent = await env.seed_engagement(org, status="revoked",
                                       revoked_at=env.clock.now() - timedelta(days=3))
    old = await env.seed_engagement(org, status="revoked",
                                    revoked_at=env.clock.now() - timedelta(days=10))
    n = await reconcile_revokes(env.state)
    assert n >= 1  # the module DB may hold other recent revokes from earlier tests
    (e,) = revoked_entries(env, recent)
    assert e.actor == "system" and dict(e.payload)["repaired"] is True
    assert revoked_entries(env, old) == []
    assert await reconcile_revokes(env.state) == 0
    assert len(revoked_entries(env, recent)) == 1  # already recorded: nothing more written


async def test_cancelled_scans_never_restart(env: Env) -> None:
    org = await env.org()
    eid = (await env.create_engagement(org)).json()["id"]
    pending = await env.seed_scan(org, eid, "pending")
    queued = await env.seed_scan(org, eid, "queued")
    running = await env.seed_scan(org, eid, "running")
    await revoke(env, org, eid)
    for sid in (pending, queued, running):
        assert (await env.get(f"/v1/scans/{sid}", org)).json()["status"] == "cancelled"
