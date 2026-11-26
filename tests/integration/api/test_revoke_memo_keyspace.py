"""DE-01: a client cannot occupy, delete or confuse the revoke memo row."""
from __future__ import annotations

import time
from typing import Any

import pytest
from api_it_support import Env, TestOrg
from api_payloads import SCAN_PAYLOAD

from vulnscope.api.idempotency import storage_key

pytestmark = pytest.mark.integration


def forms(eid: str) -> list[str]:
    return [f"revoke-record:{eid}", f"revoke-memo-v1:{eid}", f"REVOKE-RECORD:{eid}"]


async def revoke(env: Env, org: TestOrg, eid: str, reason: str = "t") -> Any:
    return await env.post(f"/v1/engagements/{eid}/revoke", org, {"reason": reason})


async def keys_count(env: Env) -> int:
    return int((await env.sql("SELECT count(*) AS n FROM idempotency_keys"))[0]["n"])


def ledger_total(env: Env, org: TestOrg, eid: str) -> int:
    return len(env.chain.entries(f"engagement:{eid}")) + len(env.chain.entries(env.intake(org)))


async def plant(env: Env, org: TestOrg, raw: str, status: int = 201) -> None:
    """Directly store a row at the CLIENT storage key of ``raw`` (bypasses the API check, as an
    older build or a hostile writer of the table would)."""
    await env.exec(
        "INSERT INTO idempotency_keys (key, org_id, request_hash, response_body,"
        " response_status, created_at) VALUES (:k,:o,'x','{}',:s,:t)",
        k=storage_key(org.org_id, raw), o=org.org_id, s=status, t=env.clock.now())


async def test_reserved_client_keys_are_rejected_without_any_write(env: Env) -> None:
    org = await env.org()
    eid = (await env.create_engagement(org)).json()["id"]
    keys_before, ledger_before = await keys_count(env), ledger_total(env, org, eid)
    for raw in forms(eid):
        r = await env.create_engagement(org, key=raw)
        assert r.status_code == 422 and r.json()["code"] == "INVALID_REQUEST"
        assert r.headers["content-type"].startswith("application/problem+json")
        s = await env.post(f"/v1/engagements/{eid}/scans", org, SCAN_PAYLOAD, key=raw)
        assert s.status_code == 422 and s.json()["code"] == "INVALID_REQUEST"
    assert await keys_count(env) == keys_before
    assert ledger_total(env, org, eid) == ledger_before
    assert len(await env.sql("SELECT id FROM engagements WHERE org_id=:o", o=org.org_id)) == 1


async def test_revoke_and_retry_succeed_after_planted_keys(env: Env) -> None:
    org = await env.org()
    eid = (await env.create_engagement(org)).json()["id"]
    for raw in forms(eid):
        await plant(env, org, raw)
    first = await revoke(env, org, eid)
    assert first.status_code == 200
    t0 = time.monotonic()
    again = await revoke(env, org, eid, "second")
    assert again.status_code == 200 and again.json() == first.json()
    assert time.monotonic() - t0 < 3.0
    assert len(env.chain.entries(f"engagement:{eid}", "engagement.revoked")) == 1


async def test_failed_record_is_repaired_despite_planted_keys(env: Env) -> None:
    org = await env.org()
    eid = (await env.create_engagement(org)).json()["id"]
    for raw in forms(eid):
        await plant(env, org, raw)
    env.chain.fail_next_appends = 1
    assert (await revoke(env, org, eid)).status_code == 503
    assert env.chain.entries(f"engagement:{eid}", "engagement.revoked") == []
    t0 = time.monotonic()
    r = await revoke(env, org, eid)
    assert r.status_code == 200 and time.monotonic() - t0 < 3.0
    (e,) = env.chain.entries(f"engagement:{eid}", "engagement.revoked")
    assert dict(e.payload)["repaired"] is True


async def test_scan_branch_repair_ignores_planted_keys(env: Env) -> None:
    org = await env.org()
    eid = (await env.create_engagement(org)).json()["id"]
    for raw in forms(eid):
        await plant(env, org, raw)
    env.chain.fail_next_appends = 1
    assert (await revoke(env, org, eid)).status_code == 503
    r = await env.post(f"/v1/engagements/{eid}/scans", org, SCAN_PAYLOAD)
    assert r.status_code == 409 and r.json()["code"] == "REVOKED"
    assert len(env.chain.entries(f"engagement:{eid}", "engagement.revoked")) == 1


async def test_a_foreign_status_row_at_the_memo_key_is_treated_as_corrupt(env: Env) -> None:
    """Defence in depth: whatever sits at the memo key with a status other than 0 or 200 is
    discarded and the revoke is recorded again, not waited on until 503."""
    from vulnscope.api.revoke_recorder import memo_key

    org = await env.org()
    eid = await env.seed_engagement(org, status="revoked")
    await env.exec(
        "INSERT INTO idempotency_keys (key, org_id, request_hash, response_body,"
        " response_status, created_at) VALUES (:k,:o,'x','{}',201,:t)",
        k=memo_key(org.org_id, eid), o=org.org_id, t=env.clock.now())
    t0 = time.monotonic()
    r = await revoke(env, org, eid)
    assert r.status_code == 200 and time.monotonic() - t0 < 3.0
    assert len(env.chain.entries(f"engagement:{eid}", "engagement.revoked")) == 1
    r2 = await revoke(env, org, eid)
    assert r2.status_code == 200 and r2.json() == r.json()


async def test_client_key_expiry_sweep_cannot_remove_the_memo(env: Env) -> None:
    """acquire() deletes an expired row at the client storage key; the memo is elsewhere."""
    org = await env.org()
    eid = (await env.create_engagement(org)).json()["id"]
    first = await revoke(env, org, eid)
    assert first.status_code == 200
    env.clock.advance(seconds=25 * 3600)
    for raw in forms(eid) + [f"k-{eid}"]:
        await env.create_engagement(org, key=raw)
    again = await revoke(env, org, eid)
    assert again.status_code == 200 and again.json() == first.json()
    assert len(env.chain.entries(f"engagement:{eid}", "engagement.revoked")) == 1
