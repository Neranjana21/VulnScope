"""AC8 (PD-18): API-key auth and role checks work; cross-org reads return 404 (T9)."""
from __future__ import annotations

import uuid
from typing import Any

import pytest
from acc_support import SCAN_PAYLOAD, World, assert_problem, strip_volatile

pytestmark = pytest.mark.acceptance

PROTECTED: list[tuple[str, str]] = [
    ("GET", "/v1/engagements/{eid}"), ("POST", "/v1/engagements"),
    ("POST", "/v1/engagements/{eid}/revoke"), ("POST", "/v1/engagements/{eid}/scans"),
    ("GET", "/v1/scans/{eid}"), ("GET", "/v1/ledger/verify?chain=intake:{eid}"),
    ("GET", "/metrics"),
]
BAD_AUTH = {
    "no-header": None,
    "basic": "Basic dXNlcjpwYXNzd29yZC1wYXNzd29yZC1wYXNzd29yZA==",
    "bearer-empty": "Bearer ",
    "bearer-31-chars": "Bearer " + "a" * 31,
    "bearer-unknown-40": "Bearer vs_test_" + "0" * 32,
    "bearer-two-tokens": "Bearer " + "a" * 40 + " " + "b" * 40,
    "bearer-control-char": "Bearer " + "a" * 40 + "\x01",
}


def _call(world: World, method: str, path: str, authz: str | None) -> Any:
    h = {} if authz is None else {"Authorization": authz}
    if method == "GET":
        return world.client.get(path, headers=h)
    return world.client.post(path, json={}, headers=h)


@pytest.mark.covers_code("UNAUTHENTICATED")
@pytest.mark.parametrize("method,path", PROTECTED)
def test_401_bodies_identical_for_every_bad_credential(world: World, method: str,
                                                       path: str) -> None:
    rid = str(uuid.uuid4())
    path = path.format(eid=rid)
    revoked = world.key(world.org("admin").org_id, "admin", revoked=True)
    cases = dict(BAD_AUTH)
    cases["revoked-key"] = f"Bearer {revoked.token}"
    seen: list[dict[str, Any]] = []
    for label, authz in cases.items():
        try:
            resp = _call(world, method, path, authz)
        except Exception:  # noqa: BLE001 - a transport refusal of a hostile header is not a 401
            if label == "bearer-control-char":
                continue
            raise
        body = assert_problem(resp, 401, "UNAUTHENTICATED")
        assert resp.headers.get("www-authenticate") == "Bearer"
        seen.append(strip_volatile(body))
    assert all(b == seen[0] for b in seen)  # missing, malformed, unknown and revoked look alike


def test_healthz_is_open_and_unknown_path_is_404_with_or_without_key(world: World) -> None:
    assert world.client.get("/healthz").status_code == 200
    assert world.client.get("/healthz").json() == {"status": "ok"}
    assert_problem(world.client.get("/v1/nope"), 404, "NOT_FOUND")
    a = world.org("admin")
    assert_problem(world.get("/v1/nope", a), 404, "NOT_FOUND")


def test_openapi_and_docs_are_not_exposed(world: World) -> None:
    for p in ("/docs", "/redoc", "/openapi.json"):
        assert world.client.get(p).status_code == 404


@pytest.mark.covers_code("FORBIDDEN_ROLE")
def test_viewer_cannot_write_but_can_read(world: World) -> None:
    admin = world.org("admin")
    viewer = world.key(admin.org_id, "viewer")
    eid = world.create(admin).json()["id"]
    chain = f"engagement:{eid}"
    before = len(world.ledger_rows(chain))
    intake_before = len(world.ledger_rows(admin.intake))
    assert_problem(world.post("/v1/engagements", viewer, {}), 403, "FORBIDDEN_ROLE")
    assert_problem(world.post(f"/v1/engagements/{eid}/revoke", viewer, {"reason": "x"}), 403,
                   "FORBIDDEN_ROLE")
    assert_problem(world.post(f"/v1/engagements/{eid}/scans", viewer, SCAN_PAYLOAD), 403,
                   "FORBIDDEN_ROLE")
    assert_problem(world.get("/metrics", viewer), 403, "FORBIDDEN_ROLE")
    # a 403 is a security-log event, never a ledger entry (ADR-0006 decision 4)
    assert len(world.ledger_rows(chain)) == before
    assert len(world.ledger_rows(admin.intake)) == intake_before
    assert world.get(f"/v1/engagements/{eid}", viewer).status_code == 200


def test_unknown_role_value_fails_closed_to_403(world: World) -> None:
    admin = world.org("admin")
    odd = world.key(admin.org_id, "superuser")
    assert_problem(world.get("/metrics", odd), 403, "FORBIDDEN_ROLE")
    assert_problem(world.post("/v1/engagements", odd, {}), 403, "FORBIDDEN_ROLE")


def test_assessor_may_create_but_not_read_metrics(world: World) -> None:
    a = world.org("assessor")
    assert world.create(a).status_code == 201
    assert_problem(world.get("/metrics", a), 403, "FORBIDDEN_ROLE")


# ---- org isolation (T9) ------------------------------------------------------------------------
@pytest.mark.covers_code("NOT_FOUND")
def test_cross_org_is_404_identical_to_unknown_id(world: World) -> None:
    a, b = world.org("admin"), world.org("admin")
    eid = world.create(a).json()["id"]
    chain = f"engagement:{eid}"
    sid = world.seed_scan(a, eid, "queued")
    rnd = str(uuid.uuid4())
    a_records = len(world.ledger_rows(chain))
    a_intake = len(world.ledger_rows(a.intake))
    b_intake = len(world.ledger_rows(b.intake))

    probes = [
        ("GET", "/v1/engagements/{}", None), ("POST", "/v1/engagements/{}/revoke", {"reason": "x"}),
        ("POST", "/v1/engagements/{}/scans", SCAN_PAYLOAD),
    ]
    for method, tmpl, body in probes:
        foreign = _send(world, b, method, tmpl.format(eid), body)
        random = _send(world, b, method, tmpl.format(rnd), body)
        f = assert_problem(foreign, 404, "NOT_FOUND")
        r = assert_problem(random, 404, "NOT_FOUND")
        assert strip_volatile(f) == strip_volatile(r)
    for tmpl in ("/v1/scans/{}", "/v1/scans/{}/findings", "/v1/scans/{}/paths",
                 "/v1/scans/{}/report"):
        f = assert_problem(world.get(tmpl.format(sid), b), 404, "NOT_FOUND")
        r = assert_problem(world.get(tmpl.format(rnd), b), 404, "NOT_FOUND")
        assert strip_volatile(f) == strip_volatile(r)
    for chain_id in (chain, a.intake, f"engagement:{rnd}", "engagement:../x", "bogus"):
        f = assert_problem(world.verify(b, chain_id), 404, "NOT_FOUND")
        assert f["detail"] == assert_problem(world.verify(b, f"engagement:{rnd}"), 404,
                                             "NOT_FOUND")["detail"]

    # nothing written anywhere: A's state is unchanged, B's intake did not grow
    assert world.get(f"/v1/engagements/{eid}", a).json()["status"] == "active"
    assert len(world.ledger_rows(chain)) == a_records == world.verify(a, chain).json()["records"]
    assert len(world.ledger_rows(a.intake)) == a_intake
    assert len(world.ledger_rows(b.intake)) == b_intake


def _send(world: World, actor: Any, method: str, path: str, body: Any) -> Any:
    return world.get(path, actor) if method == "GET" else world.post(path, actor, body)


def test_own_org_reads_still_work_after_foreign_probes(world: World) -> None:
    a, b = world.org("admin"), world.org("admin")
    eid = world.create(a).json()["id"]
    sid = world.seed_scan(a, eid, "queued")
    world.get(f"/v1/engagements/{eid}", b)
    assert world.get(f"/v1/scans/{sid}", a).status_code == 200
    assert world.get(f"/v1/scans/{sid}/findings", a).json() == {"schema_version": 1, "items": []}
    assert world.get(f"/v1/scans/{sid}/paths", a).json() == {
        "schema_version": 1, "items": [], "paths_total": 0}
    assert world.get(f"/v1/scans/{sid}/report", a).status_code == 200
    for fmt in ("html", "pdf", "xml"):
        assert_problem(world.get(f"/v1/scans/{sid}/report", a, params={"format": fmt}), 404,
                       "NOT_FOUND")


def test_same_idempotency_key_in_two_orgs_never_replays_across(world: World) -> None:
    a, b = world.org("admin"), world.org("admin")
    ra = world.create(a, key="shared-key-1")
    rb = world.create(b, key="shared-key-1")
    assert ra.status_code == rb.status_code == 201
    assert ra.json()["id"] != rb.json()["id"]
    assert "idempotent-replayed" not in rb.headers
    assert world.engagements_of(a.org_id) == 1 and world.engagements_of(b.org_id) == 1
    # the stored key never equals the raw key
    assert world.count("SELECT count(*) AS n FROM idempotency_keys WHERE key = :k",
                       k="shared-key-1") == 0


def test_verify_checkpoint_parameter_is_refused_in_every_form(world: World) -> None:
    a = world.org("admin")
    chain = a.intake
    for q in ("?chain={}&checkpoint=/etc/passwd", "?chain={}&checkpoint=", "?chain={}&checkpoint",
              "?chain={}&checkpoint=a&checkpoint=b"):
        r = world.client.get("/v1/ledger/verify" + q.format(chain), headers=a.h)
        assert_problem(r, 422, "INVALID_REQUEST")
