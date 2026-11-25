"""T9: cross-org is a uniform 404 that writes nothing; ledger verify (design 4, 7.3, PD-15)."""
from __future__ import annotations

import asyncio
import builtins
import os
import time
import uuid
from pathlib import Path

import pytest
from api_it_support import Env, make_env
from api_payloads import SCAN_PAYLOAD

from vulnscope.api.limits import Timeouts
from vulnscope.ledger.types import Checkpoint, VerifyResult

pytestmark = pytest.mark.integration


def uniform(body: dict) -> dict:
    return {k: v for k, v in body.items() if k != "request_id"}


async def test_cross_org_matrix_is_indistinguishable_from_unknown(env: Env) -> None:
    a, b = await env.org(), await env.org()
    eid = await env.seed_engagement(a)
    sid = await env.seed_scan(a, eid)
    chain_before = {k: len(v) for k, v in env.chain.chains.items()}
    rid = str(uuid.uuid4())
    calls: list[tuple[str, str, object]] = [
        ("GET", "/v1/engagements/{e}", None),
        ("POST", "/v1/engagements/{e}/revoke", {"reason": "x"}),
        ("POST", "/v1/engagements/{e}/scans", SCAN_PAYLOAD),
        ("GET", "/v1/scans/{s}", None),
        ("GET", "/v1/scans/{s}/findings", None),
        ("GET", "/v1/scans/{s}/paths", None),
        ("GET", "/v1/scans/{s}/report", None),
    ]
    for method, tmpl, body in calls:
        foreign = tmpl.format(e=eid, s=sid)
        unknown = tmpl.format(e=rid, s=rid)
        r1 = await (env.post(foreign, b, body) if method == "POST" else env.get(foreign, b))
        r2 = await (env.post(unknown, b, body) if method == "POST" else env.get(unknown, b))
        assert r1.status_code == r2.status_code == 404, tmpl
        assert r1.json()["code"] == "NOT_FOUND"
        assert uniform(r1.json()) == uniform(r2.json()), tmpl
    assert {k: len(v) for k, v in env.chain.chains.items()} == chain_before  # wrote nothing
    ok = await env.get(f"/v1/engagements/{eid}", a)
    assert ok.status_code == 200 and ok.json()["status"] == "active"
    scan_row = await env.sql("SELECT status FROM scans WHERE id=:s", s=sid)
    assert scan_row[0]["status"] == "queued"


async def test_malformed_and_overlong_ids_are_the_same_404(env: Env) -> None:
    a = await env.org()
    for bad in ("not-a-uuid", "x" * 500, "%20", "..%2f..%2fetc"):
        r = await env.get(f"/v1/engagements/{bad}", a)
        assert r.status_code == 404 and r.json()["code"] == "NOT_FOUND"


async def test_verify_cross_org_is_404_with_zero_ledger_calls(env: Env) -> None:
    a, b = await env.org(), await env.org()
    eid = await env.seed_engagement(a)
    env.chain.prefill(f"engagement:{eid}", 3)
    env.chain.calls.clear()
    for chain in (f"engagement:{eid}", f"intake:{a.org_id}", f"engagement:{uuid.uuid4()}",
                  "intake:" + str(uuid.uuid4()), "evidence:abc", "x" * 400, "engagement:%00"):
        r = await env.get("/v1/ledger/verify", b, params={"chain": chain})
        assert r.status_code == 404 and r.json()["code"] == "NOT_FOUND", chain
    assert env.chain.calls == [] and env.verify.calls == []


async def test_verify_own_chain_states_and_limitation_header(env: Env) -> None:
    a = await env.org()
    eid = await env.seed_engagement(a)
    env.chain.prefill(f"engagement:{eid}", 3)
    r = await env.get("/v1/ledger/verify", a, params={"chain": f"engagement:{eid}"})
    assert r.status_code == 200
    assert r.json() == {"result": "ok", "first_bad_seq": None, "records": 3,
                        "checkpoint_seq": None}
    assert r.headers["x-ledger-limitation"].startswith("no-checkpoint")
    for res in (VerifyResult("bad_record", 1, 3, None), VerifyResult("fork", 2, 3, None),
                VerifyResult("truncated", None, 2, 2)):
        env.verify.result = res
        r = await env.get("/v1/ledger/verify", a, params={"chain": f"engagement:{eid}"})
        assert r.json() == {"result": res.result, "first_bad_seq": res.first_bad_seq,
                            "records": res.records, "checkpoint_seq": res.checkpoint_seq}
        assert ("x-ledger-limitation" in r.headers) == (res.checkpoint_seq is None)
    env.verify.result = None
    env.checkpoints.checkpoint = Checkpoint(f"engagement:{eid}", 2,
                                            "0" * 64, env.clock.now(), "aa")
    r = await env.get("/v1/ledger/verify", a, params={"chain": f"engagement:{eid}"})
    assert r.json()["checkpoint_seq"] == 2 and "x-ledger-limitation" not in r.headers


async def test_verify_own_intake_chain_and_viewer_allowed(env: Env) -> None:
    a = await env.org()
    viewer = await env.key(a.org_id, "viewer")
    r = await env.get("/v1/ledger/verify", viewer, params={"chain": f"intake:{a.org_id}"})
    assert r.status_code == 200 and r.json()["records"] == 0


async def test_verify_query_shape(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    a = await env.org()
    opened: list[object] = []
    real_open = builtins.open
    real_os_open = os.open
    real_path_open = Path.open

    def spy_open(*args, **kw):  # type: ignore[no-untyped-def]
        opened.append(args[:1])
        return real_open(*args, **kw)

    def spy_os_open(*args, **kw):  # type: ignore[no-untyped-def]
        opened.append(args[:1])
        return real_os_open(*args, **kw)

    def spy_path_open(self, *args, **kw):  # type: ignore[no-untyped-def]
        opened.append(str(self))
        return real_path_open(self, *args, **kw)

    monkeypatch.setattr(builtins, "open", spy_open)
    monkeypatch.setattr(os, "open", spy_os_open)
    monkeypatch.setattr(Path, "open", spy_path_open)
    chain = f"intake:{a.org_id}"
    for q in (f"chain={chain}&checkpoint=/etc/passwd", f"chain={chain}&checkpoint=",
              f"chain={chain}&checkpoint", f"chain={chain}&checkpoint=a&checkpoint=b"):
        r = await env.client.get(f"/v1/ledger/verify?{q}", headers=a.h)
        assert r.status_code == 422 and r.json()["code"] == "INVALID_REQUEST", q
    r = await env.client.get("/v1/ledger/verify", headers=a.h)  # missing chain
    assert r.status_code == 422
    r = await env.client.get(f"/v1/ledger/verify?chain={chain}&chain={chain}", headers=a.h)
    assert r.status_code == 422
    r = await env.client.get("/v1/ledger/verify?chain=" + "a" * 10_000, headers=a.h)
    assert r.status_code == 404
    monkeypatch.undo()
    assert not [o for o in opened if "passwd" in str(o)]


async def test_verify_caps_record_limit_deadline_and_concurrency(api_db: object) -> None:
    e = await make_env(api_db, timeouts=Timeouts(verify_max_records=100, verify_deadline_s=0.3,
                                                 claim_poll_s=0.01))
    try:
        a = await e.org()
        eid = await e.seed_engagement(a)
        e.chain.prefill(f"engagement:{eid}", 101)
        r = await e.get("/v1/ledger/verify", a, params={"chain": f"engagement:{eid}"})
        assert r.status_code == 503 and r.json()["code"] == "UNAVAILABLE"
        e.chain.chains[f"engagement:{eid}"].clear()
        e.verify.hang = True
        t0 = time.monotonic()
        r = await e.get("/v1/ledger/verify", a, params={"chain": f"engagement:{eid}"})
        assert r.status_code == 503 and time.monotonic() - t0 < 2
        e.verify.hang = False
        e.verify.delay = 0.15
        e.state.timeouts  # noqa: B018
        # one verify per org at a time: the second concurrent one is refused immediately
        rs = await asyncio.gather(*[e.get("/v1/ledger/verify", a,
                                          params={"chain": f"engagement:{eid}"})
                                    for _ in range(3)])
        assert sorted(r.status_code for r in rs).count(200) >= 1
        assert any(r.status_code == 503 and r.headers.get("retry-after") == "2" for r in rs)
        # two orgs each verifying once concurrently both succeed
        b = await e.org()
        bid = await e.seed_engagement(b)
        rs = await asyncio.gather(
            e.get("/v1/ledger/verify", a, params={"chain": f"engagement:{eid}"}),
            e.get("/v1/ledger/verify", b, params={"chain": f"engagement:{bid}"}))
        assert [r.status_code for r in rs] == [200, 200]
    finally:
        await e.close()


async def test_verify_does_not_starve_the_event_loop(env: Env) -> None:
    a = await env.org()
    eid = await env.seed_engagement(a)
    env.chain.prefill(f"engagement:{eid}", 20_000)
    stop = asyncio.Event()
    lat: list[float] = []

    async def poll() -> None:
        while not stop.is_set():
            t = time.monotonic()
            await env.client.get("/healthz")
            lat.append(time.monotonic() - t)
            await asyncio.sleep(0.05)

    task = asyncio.create_task(poll())
    env.verify.delay = 0.0
    r = await env.get("/v1/ledger/verify", a, params={"chain": f"engagement:{eid}"})
    stop.set()
    await task
    assert r.status_code == 200 and lat
    lat.sort()
    assert lat[int(len(lat) * 0.95) - 1 if len(lat) > 1 else 0] < 0.1
