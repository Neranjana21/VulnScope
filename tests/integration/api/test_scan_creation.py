"""Scan creation (design 7.2, Fix rounds 1-2: N-01, N-04, N-06, PD-08, PD-14, PD-21, PD-22)."""
from __future__ import annotations

import asyncio
import threading
import time
from copy import deepcopy
from datetime import timedelta
from typing import Any

import pytest
from api_it_support import Env, make_env
from api_payloads import SCAN_PAYLOAD

from vulnscope.api.limits import Timeouts

pytestmark = pytest.mark.integration


def scans_path(eid: str) -> str:
    return f"/v1/engagements/{eid}/scans"


async def scan_rows(env: Env, eid: str) -> list[Any]:
    return await env.sql("SELECT id, status, options, schedule, stages FROM scans "
                         "WHERE engagement_id=:e", e=eid)


async def test_success_flow_pending_scan_created_then_queued(env: Env) -> None:
    org = await env.org()
    eid = await env.seed_engagement(org, domains=["a.lab.test", "b.lab.test"],
                                    allow=["a.lab.test", "b.lab.test"])
    r = await env.post(scans_path(eid), org, SCAN_PAYLOAD)
    assert r.status_code == 202
    body = r.json()
    assert set(body) == {"scan_id", "status"} and body["status"] == "queued"
    rows = await scan_rows(env, eid)
    assert len(rows) == 1 and rows[0]["status"] == "queued"
    assert rows[0]["options"] == {"write_tests": False} and rows[0]["schedule"] is None
    chain = env.chain.entries(f"engagement:{eid}")
    kinds = [e.kind for e in chain]
    assert kinds == ["policy.decision", "policy.decision", "scan.created"]
    assert [c["target"] for c in env.gate.calls] == ["a.lab.test", "b.lab.test"]
    assert all(c["actor"] == f"user:{org.key_id}" and c["adapter"] == "api.scan_create"
               for c in env.gate.calls)
    sc = dict(chain[-1].payload)
    assert sc["scan_id"] == body["scan_id"] and sc["write_tests"] is False
    assert sc["decision_count"] == 2
    got = await env.get(f"/v1/scans/{body['scan_id']}", org)
    assert got.status_code == 200 and got.json()["status"] == "queued"


async def test_scan_created_entry_exists_before_the_row_becomes_queued(env: Env) -> None:
    org = await env.org()
    eid = await env.seed_engagement(org)
    seen: list[str] = []
    real = env.chain.append

    async def spy(chain_id, kind, actor, payload, ts):  # type: ignore[no-untyped-def]
        if kind == "scan.created":
            rows = await scan_rows(env, eid)
            seen.extend(r["status"] for r in rows)
        return await real(chain_id, kind, actor, payload, ts)

    env.chain.append = spy  # type: ignore[method-assign]
    assert (await env.post(scans_path(eid), org, SCAN_PAYLOAD)).status_code == 202
    assert seen == ["pending"]


async def test_scan_created_append_failure_cancels_and_releases(env: Env) -> None:
    org = await env.org()
    eid = await env.seed_engagement(org)
    real = env.chain.append

    async def failing(chain_id, kind, actor, payload, ts):  # type: ignore[no-untyped-def]
        if kind == "scan.created":
            raise RuntimeError("canary-should-never-surface")
        return await real(chain_id, kind, actor, payload, ts)

    env.chain.append = failing  # type: ignore[method-assign]
    r = await env.post(scans_path(eid), org, SCAN_PAYLOAD, key="sc-fail")
    assert r.status_code == 503 and "canary" not in r.text
    assert [x["status"] for x in await scan_rows(env, eid)] == ["cancelled"]
    assert (await env.sql("SELECT count(*) AS n FROM idempotency_keys WHERE org_id=:o",
                          o=org.org_id))[0]["n"] == 0


DENY_MAP = [
    ("REVOKED", 409, "REVOKED"), ("EXPIRED", 409, "EXPIRED"),
    ("NOT_YET_VALID", 409, "TARGET_DENIED"), ("OUT_OF_SCOPE", 422, "TARGET_NOT_IN_SCOPE"),
    ("EXCLUDED", 422, "TARGET_DENIED"), ("DENY_ALWAYS_LIST", 422, "TARGET_DENIED"),
    ("DENY_PRIVATE_RANGE", 422, "TARGET_DENIED"), ("REDIRECT_DENIED", 422, "TARGET_DENIED"),
    ("RESOLVED_OUTSIDE_EXPECTED", 422, "TARGET_DENIED"),
    ("RESOLUTION_FAILED", 422, "TARGET_DENIED"), ("RATE", 429, "TARGET_DENIED"),
    ("SOME_FUTURE_RULE", 422, "TARGET_DENIED"),
]


@pytest.mark.parametrize("rule,status,code", DENY_MAP, ids=[d[0] for d in DENY_MAP])
async def test_deny_mapping_per_rule_id(env: Env, rule: str, status: int, code: str) -> None:
    org = await env.org()
    eid = await env.seed_engagement(org)
    env.gate.canned["target.lab.test"] = rule
    r = await env.post(scans_path(eid), org, SCAN_PAYLOAD)
    assert r.status_code == status and r.json()["code"] == code
    seq = r.json()["ledger_seq"]
    dec = env.chain.entries(f"engagement:{eid}")[seq]
    assert dec.kind == "policy.decision" and dec.payload["rule_id"] == rule
    assert await scan_rows(env, eid) == []


async def test_first_deny_stops_the_loop(env: Env) -> None:
    org = await env.org()
    eid = await env.seed_engagement(org, domains=["a.lab.test", "b.lab.test", "c.lab.test"],
                                    allow=["a.lab.test", "b.lab.test", "c.lab.test"])
    env.gate.canned["b.lab.test"] = "EXCLUDED"
    r = await env.post(scans_path(eid), org, SCAN_PAYLOAD)
    assert r.status_code == 422
    assert [c["target"] for c in env.gate.calls] == ["a.lab.test", "b.lab.test"]
    assert [e.payload["allowed"] for e in env.chain.entries(f"engagement:{eid}")] == [True, False]


async def test_profile_not_enabled_at_scan_time(api_db: Any) -> None:
    e = await make_env(api_db, enable_lab=False)
    try:
        org = await e.org()
        eid = await e.seed_engagement(org, profile="lab")
        r = await e.post(scans_path(eid), org, SCAN_PAYLOAD)
        assert r.status_code == 422 and r.json()["code"] == "PROFILE_NOT_ENABLED"
        dec = e.chain.entries(f"engagement:{eid}")[r.json()["ledger_seq"]]
        assert dec.kind == "policy.decision"
    finally:
        await e.close()


async def test_gate_exception_is_503_with_system_audit_entry_and_no_row(env: Env) -> None:
    org = await env.org()
    eid = await env.seed_engagement(org)
    env.gate.exc = ValueError("canary-should-never-surface")
    r = await env.post(scans_path(eid), org, SCAN_PAYLOAD, key="gx")
    assert r.status_code == 503 and r.json()["code"] == "UNAVAILABLE"
    assert "canary" not in r.text
    assert await scan_rows(env, eid) == []
    (e,) = env.chain.entries(f"engagement:{eid}", "scan.gate_error")
    assert e.actor == "system" and dict(e.payload)["reason"] == "exception"
    assert dict(e.payload)["exc_class"] == "ValueError" and "canary" not in str(dict(e.payload))
    env.gate.exc = None
    assert (await env.post(scans_path(eid), org, SCAN_PAYLOAD, key="gx")).status_code == 202


async def test_range_only_engagement_still_runs_one_lifecycle_decision(env: Env) -> None:
    org = await env.org()
    ok = await env.seed_engagement(org, domains=[], ip_ranges=["10.1.0.0/16"],
                                   allow=["10.1.0.0/16"])
    r = await env.post(scans_path(ok), org, SCAN_PAYLOAD)
    assert r.status_code == 202
    assert [c["target"] for c in env.gate.calls] == ["10.1.0.0"]
    assert env.gate.calls[0]["adapter"] == "api.scan_create.lifecycle"
    sc = dict(env.chain.entries(f"engagement:{ok}", "scan.created")[0].payload)
    assert sc["lifecycle_probe"] is True
    assert sc["range_checks"] == [{"index": 0, "verdict": "allow"}]


@pytest.mark.parametrize("kind,rule,status,code", [
    ("revoked", "REVOKED", 409, "REVOKED"), ("expired", "EXPIRED", 409, "EXPIRED"),
    ("future", "NOT_YET_VALID", 409, "TARGET_DENIED")])
async def test_range_only_lifecycle_is_decided_and_recorded(
        env: Env, kind: str, rule: str, status: int, code: str) -> None:
    org = await env.org()
    kw: dict[str, Any] = dict(domains=[], ip_ranges=["10.1.0.0/16"], allow=["10.1.0.0/16"])
    now = env.clock.now()
    if kind == "revoked":
        kw["status"] = "revoked"
    elif kind == "expired":
        kw.update(not_before=now - timedelta(days=3), not_after=now - timedelta(days=1))
    else:
        kw.update(not_before=now + timedelta(days=1), not_after=now + timedelta(days=3))
    eid = await env.seed_engagement(org, **kw)
    r = await env.post(scans_path(eid), org, SCAN_PAYLOAD)
    assert r.status_code == status and r.json()["code"] == code
    dec = env.chain.entries(f"engagement:{eid}")[r.json()["ledger_seq"]]
    assert dec.kind == "policy.decision" and dec.payload["rule_id"] == rule
    assert await scan_rows(env, eid) == []


async def test_range_overlapping_always_deny_is_rejected_at_scan_time(env: Env) -> None:
    org = await env.org()
    eid = await env.seed_engagement(org, domains=[], ip_ranges=["169.0.0.0/8"],
                                    allow=["169.0.0.0/8"])
    r = await env.post(scans_path(eid), org, SCAN_PAYLOAD)
    assert r.status_code == 422 and r.json()["code"] == "TARGET_DENIED"
    e = env.chain.entries(f"engagement:{eid}")[r.json()["ledger_seq"]]
    assert e.kind == "scan.rejected" and dict(e.payload)["code"] == "TARGET_DENIED"
    assert await scan_rows(env, eid) == []
    assert all("/" not in c["target"] for c in env.gate.calls)  # no CIDR ever in Action.target


async def test_no_cidr_ever_reaches_the_gate(env: Env) -> None:
    org = await env.org()
    eid = await env.seed_engagement(org, domains=["a.lab.test"], ip_ranges=["10.1.0.0/16"],
                                    allow=["a.lab.test", "10.1.0.0/16"])
    assert (await env.post(scans_path(eid), org, SCAN_PAYLOAD)).status_code == 202
    assert all("/" not in c["target"] for c in env.gate.calls)


async def test_openapi_host_is_gated(env: Env) -> None:
    org = await env.org()
    p = None
    eid = await env.seed_engagement(org, domains=[], allow=["api.lab.test"], payload=p)
    await env.exec("UPDATE engagements SET targets=CAST(:t AS json) WHERE id=:e",
                   t='{"domains": [], "ip_ranges": [], "openapi_url": "http://api.lab.test/spec.json"}',
                   e=eid)
    assert (await env.post(scans_path(eid), org, SCAN_PAYLOAD)).status_code == 202
    assert [c["target"] for c in env.gate.calls] == ["api.lab.test"]


async def test_zero_target_engagement_is_rejected_after_a_recorded_entry(env: Env) -> None:
    org = await env.org()
    eid = await env.seed_engagement(org, domains=[], ip_ranges=[])
    r = await env.post(scans_path(eid), org, SCAN_PAYLOAD)
    assert r.status_code == 422 and r.json()["code"] == "TARGET_NOT_IN_SCOPE"
    assert env.chain.entries(f"engagement:{eid}")[r.json()["ledger_seq"]].kind == "scan.rejected"


def bad(**over: Any) -> dict[str, Any]:
    p = deepcopy(SCAN_PAYLOAD)
    for k, v in over.items():
        if k == "write_tests":
            p["options"] = {"write_tests": v}
        else:
            p[k] = v
    return p


@pytest.mark.parametrize("payload", [
    bad(write_tests=True), bad(write_tests="true"), bad(write_tests=1), bad(write_tests="yes"),
    bad(write_tests=0), bad(write_tests="false"), bad(schedule={"x": 1}), bad(stages=[]),
    bad(stages=["discover", "discover"]), bad(stages=["discover", "x"]),
    bad(stages=["discover", "detect", "validate", "path", "path"]), bad(schema_version=2),
    {**SCAN_PAYLOAD, "extra": 1}, bad(options={"write_tests": False, "x": 1}),
])
async def test_scan_request_edges_make_zero_gate_calls(env: Env, payload: dict[str, Any]) -> None:
    org = await env.org()
    eid = await env.seed_engagement(org)
    r = await env.post(scans_path(eid), org, payload)
    assert r.status_code == 422 and r.json()["code"] == "INVALID_REQUEST"
    assert env.gate.calls == [] and await scan_rows(env, eid) == []


async def test_absent_options_default_to_no_write_tests(env: Env) -> None:
    org = await env.org()
    eid = await env.seed_engagement(org)
    r = await env.post(scans_path(eid), org, {"schema_version": 1, "stages": ["discover"]})
    assert r.status_code == 202
    assert (await scan_rows(env, eid))[0]["options"] == {"write_tests": False}


async def test_get_scan_view_statuses_and_findings_paths_report_stubs(env: Env) -> None:
    org = await env.org()
    eid = await env.seed_engagement(org)
    for st in ("pending", "queued", "running", "cancelled"):
        sid = await env.seed_scan(org, eid, st)
        r = await env.get(f"/v1/scans/{sid}", org)
        assert r.status_code == 200 and r.json()["status"] == st
        assert r.json()["engagement_id"] == eid and r.json()["schema_version"] == 1
    sid = await env.seed_scan(org, eid, "queued")
    assert (await env.get(f"/v1/scans/{sid}/findings", org)).json() == {
        "schema_version": 1, "items": []}
    assert (await env.get(f"/v1/scans/{sid}/paths", org)).json() == {
        "schema_version": 1, "items": [], "paths_total": 0}
    rep = await env.get(f"/v1/scans/{sid}/report", org)
    assert rep.status_code == 200 and rep.headers["content-type"].startswith("application/json")
    rj = rep.json()
    assert rj["findings"] == [] and rj["paths"] == [] and rj["scan_id"] == sid
    as_json = await env.get(f"/v1/scans/{sid}/report", org, params={"format": "json"})
    assert as_json.status_code == 200
    for fmt in ("html", "pdf", "xml"):
        r = await env.get(f"/v1/scans/{sid}/report", org, params={"format": fmt})
        assert r.status_code == 404 and r.json()["code"] == "NOT_FOUND"


async def test_unknown_stored_status_is_a_fixed_500_not_a_leak(env: Env) -> None:
    org = await env.org()
    eid = await env.seed_engagement(org)
    sid = await env.seed_scan(org, eid, "zzcanary-status")
    r = await env.get(f"/v1/scans/{sid}", org)
    assert r.status_code == 500 and r.json()["code"] == "INTERNAL_ERROR"
    assert "canary" not in r.text


async def test_slow_resolver_hits_the_deadline_with_a_recorded_gate_error(api_db: Any) -> None:
    e = await make_env(api_db, timeouts=Timeouts(scan_deadline_s=0.4, resolve_timeout_s=0.1,
                                                 claim_poll_s=0.01))
    try:
        org, other = await e.org(), await e.org()
        eid = await e.seed_engagement(org)
        oid = await e.seed_engagement(other)
        e.gate.hang = True
        t0 = time.monotonic()
        task = asyncio.create_task(e.post(scans_path(eid), org, SCAN_PAYLOAD, key="slow"))
        await asyncio.sleep(0.1)
        t1 = time.monotonic()
        assert (await e.client.get("/healthz")).status_code == 200
        assert (await e.get(f"/v1/engagements/{oid}", other)).status_code == 200
        assert time.monotonic() - t1 < 0.5
        r = await task
        assert r.status_code == 503 and r.json()["code"] == "UNAVAILABLE"
        assert time.monotonic() - t0 < 2.0
        (ge,) = e.chain.entries(f"engagement:{eid}", "scan.gate_error")
        assert dict(ge.payload)["reason"] == "deadline" and ge.actor == "system"
        assert not [x for x in e.chain.entries(f"engagement:{eid}") if x.kind == "policy.decision"]
        assert await scan_rows(e, eid) == []
        assert (await e.sql("SELECT count(*) AS n FROM idempotency_keys WHERE org_id=:o",
                            o=org.org_id))[0]["n"] == 0
    finally:
        await e.close()


async def test_admission_limits_concurrency_per_org_and_cleans_up(api_db: Any) -> None:
    e = await make_env(api_db, timeouts=Timeouts(admission_wait_s=0.1, claim_poll_s=0.01))
    try:
        org = await e.org()
        eid = await e.seed_engagement(org)
        e.gate.delay = 0.4
        rs = await asyncio.gather(*[e.post(scans_path(eid), org, SCAN_PAYLOAD) for _ in range(5)])
        assert e.gate.max_inflight == 2
        codes = sorted(r.status_code for r in rs)
        assert codes == [202, 202, 503, 503, 503]
        gate = e.state.gates.org
        for i in range(1000):
            p = await gate.acquire(f"org-{i}")
            p.release()
        assert gate.active_orgs() == 0
    finally:
        await e.close()


async def test_deadline_does_not_free_threads_early_and_occupancy_is_bounded(api_db: Any) -> None:
    class Probe:
        def __init__(self) -> None:
            self.ev = threading.Event()
            self.lock = threading.Lock()
            self.n = 0
            self.max = 0

        def wait(self, timeout: float) -> None:
            with self.lock:
                self.n += 1
                self.max = max(self.max, self.n)
            try:
                self.ev.wait(timeout)
            finally:
                with self.lock:
                    self.n -= 1

    e = await make_env(api_db, timeouts=Timeouts(
        scan_deadline_s=0.3, resolve_timeout_s=0.5, admission_wait_s=0.1, claim_poll_s=0.01))
    try:
        orgs = [await e.org(), await e.org()]
        engs = [await e.seed_engagement(o) for o in orgs]
        probe = Probe()
        e.gate.block = probe
        rs = await asyncio.gather(*[e.post(scans_path(engs[i % 2]), orgs[i % 2], SCAN_PAYLOAD)
                                    for i in range(4)])
        assert [r.status_code for r in rs] == [503] * 4
        assert probe.max <= 4
        r = await e.post(scans_path(engs[0]), orgs[0], SCAN_PAYLOAD)  # slots still held
        assert r.status_code == 503
        probe.ev.set()
        await asyncio.sleep(1.6)  # grace = resolve timeout (0.5) + 0.5 s after the deadline
        e.gate.block = None
        r = await e.post(scans_path(engs[0]), orgs[0], SCAN_PAYLOAD)
        assert r.status_code == 202
        assert probe.max <= 4
    finally:
        await e.close()
