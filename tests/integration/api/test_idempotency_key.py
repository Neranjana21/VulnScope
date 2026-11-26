"""Idempotency (design 5, PD-11, PD-12, 12.2): replay, conflict, cross-org, concurrency, claims."""
from __future__ import annotations

import asyncio
from datetime import timedelta

import pytest
from api_it_support import Env
from api_payloads import SCAN_PAYLOAD, valid_payload

from vulnscope.api.idempotency import request_hash, storage_key

pytestmark = pytest.mark.integration


async def test_same_key_same_body_replays_original(env: Env) -> None:
    org = await env.org()
    p = valid_payload(env.clock.now())
    r1 = await env.create_engagement(org, p, key="k-1")
    r2 = await env.create_engagement(org, p, key="k-1")
    assert r1.status_code == r2.status_code == 201 and r1.json() == r2.json()
    assert "idempotent-replayed" not in r1.headers
    assert r2.headers["idempotent-replayed"] == "true"
    assert r1.headers["x-request-id"] != r2.headers["x-request-id"]
    assert len(env.chain.entries(f"engagement:{r1.json()['id']}")) == 1
    assert (await env.sql("SELECT count(*) AS n FROM engagements WHERE org_id=:o",
                          o=org.org_id))[0]["n"] == 1


async def test_same_key_different_body_is_conflict(env: Env) -> None:
    org = await env.org()
    r1 = await env.create_engagement(org, valid_payload(env.clock.now()), key="k-2")
    r2 = await env.create_engagement(org, valid_payload(env.clock.now()), key="k-2")
    assert r1.status_code == 201
    assert r2.status_code == 409 and r2.json()["code"] == "IDEMPOTENCY_CONFLICT"


async def test_same_key_on_another_endpoint_is_conflict(env: Env) -> None:
    org = await env.org()
    eid = await env.seed_engagement(org)
    r1 = await env.post(f"/v1/engagements/{eid}/scans", org, SCAN_PAYLOAD, key="k-3")
    assert r1.status_code == 202
    r2 = await env.create_engagement(org, valid_payload(env.clock.now()), key="k-3")
    assert r2.status_code == 409 and r2.json()["code"] == "IDEMPOTENCY_CONFLICT"


async def test_no_key_creates_two_resources(env: Env) -> None:
    org = await env.org()
    p = valid_payload(env.clock.now())
    a, b = await env.create_engagement(org, p), await env.create_engagement(org, p)
    assert a.status_code == b.status_code == 201 and a.json()["id"] != b.json()["id"]


async def test_replayed_rejection_writes_one_intake_entry(env: Env) -> None:
    org = await env.org()
    p = valid_payload(env.clock.now())
    p["authorization"]["confirmed"] = False
    r1 = await env.create_engagement(org, p, key="k-4")
    r2 = await env.create_engagement(org, p, key="k-4")
    assert r1.status_code == r2.status_code == 422
    assert r1.json()["code"] == r2.json()["code"] == "AUTH_NOT_CONFIRMED"
    assert r1.json()["ledger_seq"] == r2.json()["ledger_seq"]
    assert r2.headers["idempotent-replayed"] == "true"
    assert len(env.chain.entries(env.intake(org))) == 1


async def test_key_syntax_is_enforced(env: Env) -> None:
    org = await env.org()
    p = valid_payload(env.clock.now())
    assert (await env.create_engagement(org, p, key="k" * 256)).status_code == 422
    r = await env.create_engagement(org, p, key="k" * 255)
    assert r.status_code == 201
    h = {**org.h, "Content-Type": "application/json"}
    import json as _j

    r = await env.client.post("/v1/engagements", content=_j.dumps(p), headers=[
        *h.items(), ("Idempotency-Key", "a"), ("Idempotency-Key", "b")])  # type: ignore[arg-type]
    assert r.status_code == 422 and r.json()["code"] == "INVALID_REQUEST"


async def test_cross_org_same_key_never_replays_across_orgs(env: Env) -> None:
    a, b = await env.org(), await env.org()
    pa, pb = valid_payload(env.clock.now()), valid_payload(env.clock.now())
    ra = await env.create_engagement(a, pa, key="shared-key")
    rb = await env.create_engagement(b, pb, key="shared-key")
    assert ra.status_code == rb.status_code == 201 and ra.json()["id"] != rb.json()["id"]
    rb2 = await env.create_engagement(b, pa, key="shared-key")  # B posting A's exact body
    assert rb2.status_code == 409  # different body for B's own key, never A's stored response
    rows = await env.sql("SELECT key, org_id FROM idempotency_keys WHERE org_id IN (:a,:b)",
                         a=a.org_id, b=b.org_id)
    assert len(rows) == 2 and all(r["key"] != "shared-key" for r in rows)
    assert {r["key"] for r in rows} == {storage_key(a.org_id, "shared-key"),
                                        storage_key(b.org_id, "shared-key")}


async def test_concurrent_same_body_creates_exactly_one_resource(env: Env) -> None:
    org = await env.org()
    p = valid_payload(env.clock.now())
    rs = await asyncio.gather(*[env.create_engagement(org, p, key="conc-1") for _ in range(30)])
    assert [r.status_code for r in rs] == [201] * 30
    assert len({r.json()["id"] for r in rs}) == 1
    assert (await env.sql("SELECT count(*) AS n FROM engagements WHERE org_id=:o",
                          o=org.org_id))[0]["n"] == 1


async def test_concurrent_different_bodies_one_wins_rest_conflict(env: Env) -> None:
    org = await env.org()
    rs = await asyncio.gather(*[
        env.create_engagement(org, valid_payload(env.clock.now(), suffix=f"-{i}"), key="conc-2")
        for i in range(30)])
    codes = sorted(r.status_code for r in rs)
    assert codes == [201] + [409] * 29
    assert all(r.json()["code"] == "IDEMPOTENCY_CONFLICT" for r in rs if r.status_code == 409)


async def test_stale_in_progress_claim_is_reclaimed(env: Env) -> None:
    org = await env.org()
    p = valid_payload(env.clock.now())
    key = storage_key(org.org_id, "stale-1")
    h = request_hash("POST", "/v1/engagements", p)
    await env.exec(
        "INSERT INTO idempotency_keys (key, org_id, request_hash, response_body, response_status,"
        " created_at) VALUES (:k, :o, :h, '{}', 0, :t)",
        k=key, o=org.org_id, h=h, t=env.clock.now() - timedelta(seconds=120))
    r = await env.create_engagement(org, p, key="stale-1")
    assert r.status_code == 201


async def test_fresh_in_progress_claim_makes_the_caller_wait_then_conflict(env: Env) -> None:
    from vulnscope.api.limits import Timeouts

    e2 = await __import__("api_it_support").make_env(
        env.db, timeouts=Timeouts(claim_poll_s=0.01, claim_wait_s=0.3))
    try:
        org = await e2.org()
        p = valid_payload(e2.clock.now())
        key = storage_key(org.org_id, "fresh-1")
        await e2.exec(
            "INSERT INTO idempotency_keys (key, org_id, request_hash, response_body,"
            " response_status, created_at) VALUES (:k, :o, :h, '{}', 0, :t)",
            k=key, o=org.org_id, h=request_hash("POST", "/v1/engagements", p), t=e2.clock.now())
        r = await e2.create_engagement(org, p, key="fresh-1")
        assert r.status_code == 409 and r.json()["code"] == "IDEMPOTENCY_CONFLICT"
        assert r.headers["retry-after"] == "1"
    finally:
        await e2.close()


async def test_expired_row_is_dropped_lazily(env: Env) -> None:
    org = await env.org()
    p = valid_payload(env.clock.now())
    await env.create_engagement(org, p, key="old-1")
    env.clock.advance(hours=25)
    q = valid_payload(env.clock.now())
    r = await env.create_engagement(org, q, key="old-1")
    assert r.status_code == 201  # the 24 h window ended, a different body is not a conflict


async def test_winner_failure_releases_the_claim(env: Env) -> None:
    org = await env.org()
    p = valid_payload(env.clock.now())
    env.chain.fail_next_appends = 1
    assert (await env.create_engagement(org, p, key="rel-1")).status_code == 503
    assert (await env.sql("SELECT count(*) AS n FROM idempotency_keys WHERE org_id=:o",
                          o=org.org_id))[0]["n"] == 0
    assert (await env.create_engagement(org, p, key="rel-1")).status_code == 201


async def test_transient_denials_are_not_replayed_but_revoked_is(env: Env) -> None:
    org = await env.org()
    eid = await env.seed_engagement(org, not_before=env.clock.now() + timedelta(hours=1),
                                    not_after=env.clock.now() + timedelta(days=2))
    r1 = await env.post(f"/v1/engagements/{eid}/scans", org, SCAN_PAYLOAD, key="tr-1")
    assert r1.status_code == 409 and r1.json()["code"] == "TARGET_DENIED"
    env.clock.advance(hours=2)
    r2 = await env.post(f"/v1/engagements/{eid}/scans", org, SCAN_PAYLOAD, key="tr-1")
    assert r2.status_code == 202 and "idempotent-replayed" not in r2.headers

    dead = await env.seed_engagement(org, status="revoked")
    a = await env.post(f"/v1/engagements/{dead}/scans", org, SCAN_PAYLOAD, key="tr-2")
    n = len(env.chain.entries(f"engagement:{dead}"))
    b = await env.post(f"/v1/engagements/{dead}/scans", org, SCAN_PAYLOAD, key="tr-2")
    assert a.status_code == b.status_code == 409 and a.json()["code"] == "REVOKED"
    assert b.headers["idempotent-replayed"] == "true"
    assert len(env.chain.entries(f"engagement:{dead}")) == n

    c = await env.seed_engagement(org, domains=["target.lab.test"], deny=["target.lab.test"])
    x = await env.post(f"/v1/engagements/{c}/scans", org, SCAN_PAYLOAD, key="tr-3")
    n = len(env.chain.entries(f"engagement:{c}"))
    y = await env.post(f"/v1/engagements/{c}/scans", org, SCAN_PAYLOAD, key="tr-3")
    assert x.status_code == y.status_code == 422 and "idempotent-replayed" not in y.headers
    assert len(env.chain.entries(f"engagement:{c}")) > n  # a fresh decision per attempt (rule 8)
