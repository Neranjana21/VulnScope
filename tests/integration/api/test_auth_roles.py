"""AC8: API-key auth and role checks (design 3, PD-09, PD-10, PD-19, PD-20, N-07)."""
from __future__ import annotations

import json
import logging

import pytest
from api_it_support import Env
from api_payloads import SCAN_PAYLOAD

pytestmark = pytest.mark.integration

CANARY_TOKEN = "vs_test_" + "c0ffee" * 5 + "ab"  # 40 chars, well-formed, unknown


def strip(body: dict) -> dict:
    return {k: v for k, v in body.items() if k not in ("request_id", "instance")}


async def test_401_cases_have_identical_bodies(env: Env) -> None:
    org = await env.org()
    revoked = await env.key(org.org_id, "admin", revoked=True)
    path = "/v1/engagements/whatever"
    variants = [
        {},
        {"Authorization": "Basic dXNlcjpwYXNz"},
        {"Authorization": "Bearer"},
        {"Authorization": "Bearer " + "a" * 31},
        {"Authorization": f"Bearer {CANARY_TOKEN}"},
        revoked.h,
    ]
    bodies = []
    for h in variants:
        r = await env.client.get(path, headers=h)
        assert r.status_code == 401, h
        assert r.headers["www-authenticate"] == "Bearer"
        assert r.headers["content-type"].startswith("application/problem+json")
        assert r.json()["code"] == "UNAUTHENTICATED"
        bodies.append(strip(r.json()))
    assert all(b == bodies[0] for b in bodies)


async def test_health_is_open_and_minimal(env: Env) -> None:
    r = await env.client.get("/healthz")
    assert r.status_code == 200 and r.json() == {"status": "ok"}


async def test_unknown_route_is_404_without_a_key(env: Env) -> None:
    r = await env.client.get("/v1/nothing-here")
    assert r.status_code == 404 and r.json()["code"] == "NOT_FOUND"


async def test_viewer_cannot_write(env: Env) -> None:
    admin = await env.org()
    viewer = await env.key(admin.org_id, "viewer")
    eid = await env.seed_engagement(admin)
    for path, body in [
        ("/v1/engagements", {}),
        (f"/v1/engagements/{eid}/revoke", {"reason": "x"}),
        (f"/v1/engagements/{eid}/scans", SCAN_PAYLOAD),
    ]:
        r = await env.post(path, viewer, body)
        assert r.status_code == 403 and r.json()["code"] == "FORBIDDEN_ROLE", path
    r = await env.get(f"/v1/engagements/{eid}", viewer)
    assert r.status_code == 200 and r.json()["id"] == eid


async def test_assessor_can_write_but_not_read_metrics(env: Env) -> None:
    admin = await env.org()
    assessor = await env.key(admin.org_id, "assessor")
    r = await env.create_engagement(assessor)
    assert r.status_code == 201
    r = await env.get("/metrics", assessor)
    assert r.status_code == 403 and r.json()["code"] == "FORBIDDEN_ROLE"


async def test_unknown_role_value_fails_closed(env: Env) -> None:
    admin = await env.org()
    odd = await env.key(admin.org_id, "superuser")
    r = await env.get("/v1/engagements/x", odd)
    assert r.status_code == 403 and r.json()["code"] == "FORBIDDEN_ROLE"


async def test_metrics_stub_has_no_counters_and_is_org_independent(env: Env) -> None:
    a, b = await env.org(), await env.org()
    await env.client.get("/v1/engagements/x")  # an auth failure moves a counter
    ra, rb = await env.get("/metrics", a), await env.get("/metrics", b)
    assert ra.status_code == rb.status_code == 200
    assert ra.headers["content-type"].startswith("text/plain")
    assert ra.text == rb.text and "vulnscope_events_total" not in ra.text
    viewer = await env.key(a.org_id, "viewer")
    assert (await env.get("/metrics", viewer)).status_code == 403


async def test_security_events_logged_with_allowlisted_fields_only(
        env: Env, caplog: pytest.LogCaptureFixture) -> None:
    a, b = await env.org(), await env.org()
    viewer = await env.key(a.org_id, "viewer")
    eid = await env.seed_engagement(a)
    with caplog.at_level(logging.DEBUG):
        await env.client.get("/v1/engagements/x")                       # missing
        await env.post("/v1/engagements", viewer, {})                    # role denied
        await env.get(f"/v1/engagements/{eid}", b)                       # cross-org
    events = [json.loads(r.getMessage()) for r in caplog.records if r.name == "vulnscope.api"]
    by = {e["event"]: e for e in events}
    assert by["auth_failed"]["reason"] == "missing"
    assert by["role_denied"]["role"] == "viewer"
    assert by["cross_org_miss"]["route"] == "/v1/engagements/{id}"
    from vulnscope.api.logging import ALLOWED_FIELDS

    for e in events:
        assert set(e) <= ALLOWED_FIELDS | {"event"}
    blob = json.dumps(events) + str([r.__dict__ for r in caplog.records])
    if eid in json.dumps(events) or a.token in blob or b.token in blob or viewer.token in blob:
        pytest.fail("leak")
    c = env.state.counters
    assert c["auth_failed"] == 1 and c["role_denied"] == 1 and c["cross_org_miss"] == 1


async def test_auth_failure_makes_exactly_one_db_query_for_unknown_and_none_for_malformed(
        env: Env) -> None:
    from sqlalchemy import event

    seen: list[str] = []

    def hook(conn, cursor, statement, params, context, executemany):  # type: ignore[no-untyped-def]
        seen.append(statement)

    event.listen(env.engine.sync_engine, "before_cursor_execute", hook)
    try:
        for h in ({}, {"Authorization": "Basic x"}, {"Authorization": "Bearer short"}):
            await env.client.get("/v1/engagements/x", headers=h)
        assert seen == []
        await env.client.get("/v1/engagements/x",
                             headers={"Authorization": f"Bearer {CANARY_TOKEN}"})
        assert len([s for s in seen if "api_keys" in s]) == 1
    finally:
        event.remove(env.engine.sync_engine, "before_cursor_execute", hook)


async def test_auth_precedes_body_handling(env: Env) -> None:
    org = await env.org()
    viewer = await env.key(org.org_id, "viewer")
    eid = await env.seed_engagement(org)
    for path in ("/v1/engagements", f"/v1/engagements/{eid}/revoke",
                 f"/v1/engagements/{eid}/scans"):
        for raw, ct in [(b"{not json", "application/json"), (b"x" * 100_000, "application/json"),
                        (b"{}", "text/plain")]:
            r = await env.client.post(path, content=raw, headers={"Content-Type": ct})
            assert r.status_code == 401, (path, ct)
        r = await env.client.post(path, content=b"x" * 300_000,
                                  headers={"Content-Type": "application/json"})
        assert r.status_code == 413  # the only pre-auth body response: declared length
        r = await env.client.post(path, content=b"{not json", headers={
            **viewer.h, "Content-Type": "application/json"})
        assert r.status_code == 403


async def test_idempotency_conflict_is_a_security_log_event_not_a_ledger_entry(
        env: Env, caplog: pytest.LogCaptureFixture) -> None:
    from api_payloads import valid_payload

    org = await env.org()
    await env.create_engagement(org, valid_payload(env.clock.now()), key="conf-1")
    appended = env.chain.count("append")
    with caplog.at_level(logging.DEBUG):
        r = await env.create_engagement(org, valid_payload(env.clock.now()), key="conf-1")
    assert r.status_code == 409
    events = [json.loads(x.getMessage()) for x in caplog.records if x.name == "vulnscope.api"]
    assert [e["event"] for e in events] == ["idempotency_conflict"]
    assert env.state.counters["idempotency_conflict"] == 1
    assert env.chain.count("append") == appended  # rule 8 reading: not a ledger event
