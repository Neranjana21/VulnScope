"""Hostile input through the real app, auth floods and the reserved revoke slots, leaks, limits
(PD-03, PD-04, PD-10, PD-24, N-03, N-07)."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import stat
import subprocess
import tempfile
import time
from contextlib import AsyncExitStack
from typing import Any

import pytest
from api_doubles import BackendFailure
from api_it_support import Env, make_env
from api_payloads import SCAN_PAYLOAD, valid_payload

from vulnscope.api.limits import Timeouts

pytestmark = pytest.mark.integration

TOK = "vs_test_" + "d" * 32


async def test_hostile_json_through_the_real_app_never_5xx_and_never_ledgers(env: Env) -> None:
    org = await env.org()
    rows = [b"[" * 100_000, b'{"a":' + b"9" * 5000 + b"}", b"NaN",
            b'{"scope":{"rate_limit_rps":NaN}}',
            b'{"scope":{"rate_limit_rps":Infinity}}', b'{"name":"\\ud800"}', b'{"name":"\\u0000"}',
            json.dumps({f"u{i}": 1 for i in range(20_000)}).encode(), b"\xef\xbb\xbf{}", b"\xff",
            b'{"a":1,"a":2}', b"", b'{"x":']
    for raw in rows:
        r = await env.post("/v1/engagements", org, raw=raw)
        assert r.status_code in (400, 413, 422), raw[:20]
        assert r.json()["code"] in ("INVALID_REQUEST", "UNKNOWN_FIELD")
        assert (await env.client.get("/healthz")).status_code == 200
    assert not [c for c in env.chain.chains if c.startswith("engagement:")]
    # 20 000 unknown fields is a contract-coded rejection at most once on the org's intake chain
    assert len(env.chain.entries(env.intake(org))) <= len(rows)
    assert (await env.sql("SELECT count(*) AS n FROM engagements WHERE org_id=:o",
                          o=org.org_id))[0]["n"] == 0


async def test_oversize_and_content_type(env: Env) -> None:
    org = await env.org()
    r = await env.client.post("/v1/engagements", content=b"{}",
                              headers={**org.h, "Content-Type": "text/plain"})
    assert r.status_code == 415 and r.json()["code"] == "INVALID_REQUEST"
    r = await env.client.post("/v1/engagements", content=b"x" * 300_000, headers={
        **org.h, "Content-Type": "application/json"})
    assert r.status_code == 413
    r = await env.client.post("/v1/engagements", content=b"", headers={
        **org.h, "Content-Type": "application/json"})
    assert r.status_code == 400


async def test_exception_text_never_reaches_response_logs_or_ledger(
        env: Env, caplog: pytest.LogCaptureFixture) -> None:
    org = await env.org()
    canary = "CANARY-leak-77aa"
    p = valid_payload(env.clock.now())
    p["name"] = canary
    env.chain.fail_always = True  # BackendFailure text carries a canary-should-never-surface
    with caplog.at_level(logging.DEBUG):
        r = await env.create_engagement(org, p)
        r2 = await env.client.get("/v1/engagements/x", headers={"Authorization": f"Bearer {TOK}"})
    assert r.status_code == 503 and r2.status_code == 401
    bad = [canary, "canary-should-never-surface", org.token, TOK]
    haystack = r.text + r2.text + str(dict(r.headers)) + json.dumps(
        [e.payload for ch in env.chain.chains.values() for e in ch], default=str) + "".join(
        f"{rec.getMessage()}{rec.exc_text}{rec.args}{rec.exc_info}" for rec in caplog.records)
    if any(b in haystack for b in bad):
        pytest.fail("leak")
    assert env.app.debug is False


async def test_database_error_text_has_no_parameters_or_values(
        env: Env, caplog: pytest.LogCaptureFixture) -> None:
    from sqlalchemy import event

    org = await env.org()
    canary = "CANARY-db-55bb"

    def boom(conn, cursor, statement, params, context, executemany):  # type: ignore[no-untyped-def]
        if statement.lstrip().upper().startswith("INSERT INTO ENGAGEMENTS"):
            raise RuntimeError(f"{canary} {params}")

    event.listen(env.engine.sync_engine, "before_cursor_execute", boom)
    try:
        p = valid_payload(env.clock.now())
        p["name"] = canary
        with caplog.at_level(logging.DEBUG):
            r = await env.create_engagement(org, p)
    finally:
        event.remove(env.engine.sync_engine, "before_cursor_execute", boom)
    assert r.status_code in (500, 503)
    blob = r.text + "".join(f"{x.getMessage()}{x.exc_text}{x.args}" for x in caplog.records)
    if canary in blob or org.token in blob:
        pytest.fail("leak")


async def test_real_datalength_error_text_has_no_parameters(env: Env) -> None:
    from sqlalchemy import text
    from sqlalchemy.exc import DBAPIError

    try:
        async with env.engine.begin() as c:
            await c.execute(text("INSERT INTO orgs (id, name, created_at, updated_at) "
                                 "VALUES (:i, :n, now(), now())"),
                            {"i": "x" * 100, "n": "CANARY-param-1"})
    except DBAPIError as exc:
        assert "[parameters:" not in str(exc)
        assert "CANARY-param-1" not in str(exc)
    else:  # pragma: no cover
        pytest.fail("expected a DataError")


async def test_no_migrator_secret_leak_in_responses_logs_or_ledger(
        env: Env, caplog: pytest.LogCaptureFixture) -> None:
    """N-07: the scratch-mode process env holds the migrator DSN; nothing may carry it. Boolean
    check via grep -F -f on a mode-600 temp file; no value is printed."""
    from urllib.parse import urlsplit

    from stress_db_secrets import reveal

    admin_url = str(reveal(env.db.admin_url))  # the migrator DSN of the scratch database
    secrets_ = [admin_url]
    parts = urlsplit(admin_url)
    if parts.password:
        secrets_.append(parts.password)
    assert len(secrets_[-1]) >= 8
    org = await env.org()
    eid = await env.seed_engagement(org)
    with caplog.at_level(logging.DEBUG):
        out: list[str] = []
        for coro in (env.create_engagement(org), env.get(f"/v1/engagements/{eid}", org),
                     env.get("/v1/engagements/nope", org), env.client.get("/v1/engagements/x"),
                     env.post(f"/v1/engagements/{eid}/scans", org, SCAN_PAYLOAD),
                     env.post("/v1/engagements", org, raw=b"{")):
            r = await coro
            out.append(f"{dict(r.headers)}{r.text}")
        env.chain.fail_always = True
        r = await env.create_engagement(org)
        out.append(f"{dict(r.headers)}{r.text}")
    out.append("".join(f"{x.getMessage()}{x.exc_text}{x.args}" for x in caplog.records))
    out.append(json.dumps([e.payload for ch in env.chain.chains.values() for e in ch], default=str))
    fd, needle = tempfile.mkstemp()
    fd2, hay = tempfile.mkstemp()
    try:
        os.fchmod(fd, 0o600)
        os.fchmod(fd2, 0o600)
        assert stat.S_IMODE(os.stat(needle).st_mode) == 0o600
        os.write(fd, ("\n".join(secrets_) + "\n").encode())
        os.write(fd2, "\n".join(out).encode())
        os.close(fd)
        os.close(fd2)
        rc = subprocess.run(["grep", "-F", "-q", "-f", needle, hay], check=False).returncode
        assert rc == 1, "leak" if rc == 0 else "grep error"
    finally:
        os.unlink(needle)
        os.unlink(hay)


async def test_auth_flood_valid_callers_are_served_or_fast_503(env: Env) -> None:
    org = await env.org()
    eid = await env.seed_engagement(org)
    flood = [env.client.get("/v1/engagements/x", headers={"Authorization": f"Bearer {TOK}{i:04d}"})
             for i in range(500)]

    async def valid() -> tuple[int, float]:
        t = time.monotonic()
        r = await env.get(f"/v1/engagements/{eid}", org)
        return r.status_code, time.monotonic() - t

    res = await asyncio.gather(*flood, *[valid() for _ in range(20)])
    assert all(r.status_code in (401, 503) for r in res[:500])  # type: ignore[union-attr]
    assert any(r.status_code == 401 for r in res[:500])  # type: ignore[union-attr]
    for code, dt in res[500:]:  # type: ignore[misc]
        assert code in (200, 503) and dt < 3.0


async def test_auth_flood_revoke_reserved_slots(api_db: Any) -> None:
    """N-03: revoke has its own reserved AuthGate slots; saturating the shared ones does not
    block it. The mutant (no reservation) must fail the same scenario."""
    async def scenario(reserved: int) -> tuple[int, int]:
        e = await make_env(api_db, timeouts=Timeouts(auth_inflight=6, auth_reserved=reserved,
                                                     auth_queue_wait_s=0.2, claim_poll_s=0.01))
        try:
            org = await e.org()
            eid = (await e.create_engagement(org)).json()["id"]
            async with AsyncExitStack() as stack:
                for _ in range(6):  # saturate every shared slot
                    await stack.enter_async_context(e.state.gates.auth.slot(reserved_ok=False))
                other = await e.get(f"/v1/engagements/{eid}", org)
                revoke = await e.post(f"/v1/engagements/{eid}/revoke", org, {"reason": "x"})
            return other.status_code, revoke.status_code
        finally:
            await e.close()

    other, revoke = await scenario(2)
    assert other == 503 and revoke == 200
    other, revoke = await scenario(0)  # mutant: without reservation revoke is blocked too
    assert other == 503 and revoke == 503


async def test_revoke_succeeds_during_a_real_unauthenticated_flood(env: Env) -> None:
    org = await env.org()
    eid = (await env.create_engagement(org)).json()["id"]
    flood = [env.client.get("/v1/engagements/x", headers={"Authorization": f"Bearer {TOK}{i:04d}"})
             for i in range(500)]

    async def rv() -> int:
        await asyncio.sleep(0.01)
        t = time.monotonic()
        r = await env.post(f"/v1/engagements/{eid}/revoke", org, {"reason": "x"})
        assert time.monotonic() - t < 3.0
        return r.status_code

    res = await asyncio.gather(rv(), *flood)
    assert res[0] == 200


async def test_pool_does_not_leak_after_cancellation(env: Env) -> None:
    org = await env.org()
    eid = await env.seed_engagement(org)
    tasks = [asyncio.create_task(env.get(f"/v1/engagements/{eid}", org)) for _ in range(100)]
    await asyncio.sleep(0.02)
    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    for _ in range(15):
        assert (await env.get(f"/v1/engagements/{eid}", org)).status_code == 200


async def test_pool_no_deadlock_under_60_concurrent_creates(env: Env) -> None:
    org = await env.org()
    env.chain.append_delay = 0.02  # a ledger call must never hold a DB connection
    rs = await asyncio.gather(*[env.create_engagement(org, valid_payload(env.clock.now()))
                                for _ in range(60)])
    assert [r.status_code for r in rs] == [201] * 60


async def test_lock_timeout_gives_503_not_a_hang(api_db: Any) -> None:
    e = await make_env(api_db, timeouts=Timeouts(lock_timeout_ms=300, statement_timeout_ms=2000,
                                                 claim_poll_s=0.01))
    try:
        org = await e.org()
        eid = await e.seed_engagement(org)
        async with e.engine.connect() as holder:
            tx = await holder.begin()
            from sqlalchemy import text

            await holder.execute(text("SELECT id FROM engagements WHERE id=:e FOR UPDATE"),
                                 {"e": eid})
            t0 = time.monotonic()
            r1 = await e.post(f"/v1/engagements/{eid}/revoke", org, {"reason": "x"})
            r2 = await e.post(f"/v1/engagements/{eid}/scans", org, SCAN_PAYLOAD)
            await tx.rollback()
        assert r1.status_code == 503 and r2.status_code == 503
        assert time.monotonic() - t0 < 3.0
    finally:
        await e.close()


async def test_db_statements_stay_inside_the_audited_set(env: Env) -> None:
    from sqlalchemy import event

    seen: list[str] = []
    org = await env.org()
    viewer = await env.key(org.org_id, "viewer")

    def hook(conn, cursor, statement, params, context, executemany):  # type: ignore[no-untyped-def]
        seen.append(" ".join(statement.split()).upper())

    event.listen(env.engine.sync_engine, "before_cursor_execute", hook)
    try:
        env_id = (await env.create_engagement(org, key="aud-1")).json()["id"]
        await env.post(f"/v1/engagements/{env_id}/scans", org, SCAN_PAYLOAD, key="aud-2")
        await env.post(f"/v1/engagements/{env_id}/revoke", org, {"reason": "x"})
        await env.get(f"/v1/engagements/{env_id}", viewer)
    finally:
        event.remove(env.engine.sync_engine, "before_cursor_execute", hook)
    api_stmts = [s for s in seen if not s.startswith(("SET LOCAL", "SELECT 1", "BEGIN"))
                 and ("ORGS" not in s.split("FROM")[0])]
    for s in api_stmts:
        if s.startswith("DELETE"):
            assert "IDEMPOTENCY_KEYS" in s, s
        if s.startswith("UPDATE"):
            assert any(t in s for t in ("ENGAGEMENTS", "SCANS", "IDEMPOTENCY_KEYS")), s
        if s.startswith("INSERT"):
            assert any(t in s for t in ("ENGAGEMENTS", "SCANS", "IDEMPOTENCY_KEYS")), s
        assert "API_KEYS" not in s or s.startswith("SELECT"), s
    assert not [s for s in seen if "DELETE FROM ENGAGEMENTS" in s or "DELETE FROM SCANS" in s]


async def test_cors_headers_are_never_sent(env: Env) -> None:
    org = await env.org()
    r = await env.client.options("/v1/engagements", headers={
        **org.h, "Origin": "http://evil.example", "Access-Control-Request-Method": "POST"})
    assert not [h for h in r.headers if h.lower().startswith("access-control-")]


async def test_every_error_class_is_problem_json_end_to_end(env: Env) -> None:
    org = await env.org()
    env.chain.fail_always = True
    calls = [env.client.get("/nope"), env.client.delete("/v1/engagements"),
             env.client.get("/v1/engagements/x"), env.get("/v1/ledger/verify", org),
             env.create_engagement(org), env.client.get("/v1/engagements/")]
    for r in await asyncio.gather(*calls):
        assert r.headers["content-type"].startswith("application/problem+json"), r.url
        body = r.json()
        assert {"type", "title", "status", "detail", "instance", "code", "request_id"} <= set(body)
        assert "loc" not in body and not isinstance(body["detail"], list)
    assert isinstance(BackendFailure("x"), Exception)
    _ = os
