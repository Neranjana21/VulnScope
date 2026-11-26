"""AC6: engagement creation rejects every contract case with the right code and records it on the
intake chain; success writes engagement.created first (design 7.1, PD-05, PD-18)."""
from __future__ import annotations

import json
from collections.abc import Callable
from datetime import timedelta
from typing import Any

import pytest
from api_it_support import Env, make_env
from api_payloads import FMT, valid_payload

pytestmark = pytest.mark.integration

PROBLEM_KEYS = {"type", "title", "status", "detail", "instance", "code", "request_id",
                "ledger_seq"}
FORBIDDEN_PAYLOAD_KEYS = {"authorization", "cookie", "set-cookie", "proxy-authorization",
                          "password", "secret", "token"}


def S(path: list[str], value: Any) -> Callable[[dict[str, Any]], None]:
    def f(p: dict[str, Any]) -> None:
        cur = p
        for k in path[:-1]:
            cur = cur[k]
        cur[path[-1]] = value

    return f


def _del_window(p: dict[str, Any]) -> None:
    del p["scope"]["window"]


def _del_not_after(p: dict[str, Any]) -> None:
    del p["scope"]["window"]["not_after"]


def _extra_root(p: dict[str, Any]) -> None:
    p["foo_canary"] = 1


def _extra_scope(p: dict[str, Any]) -> None:
    p["scope"]["foo_canary"] = 1


def _secret_ref(p: dict[str, Any]) -> None:
    p["identities"] = [{"label": "a", "role": "r",
                        "auth": {"type": "bearer", "secret_ref": "ref://A/b"}}]


def _meta_allowed(p: dict[str, Any]) -> None:
    p["targets"]["domains"] = ["169.254.169.254"]
    p["scope"]["allow"] = ["169.254.169.254"]


def _two(p: dict[str, Any]) -> None:
    p["authorization"]["confirmed"] = False
    p["scope"]["allow"] = []


def _too_long(p: dict[str, Any]) -> None:
    from datetime import datetime

    nb = datetime.strptime(p["scope"]["window"]["not_before"], FMT)
    p["scope"]["window"]["not_after"] = (nb + timedelta(days=90, seconds=1)).strftime(FMT)


def _expired(p: dict[str, Any]) -> None:
    from datetime import UTC, datetime

    p["scope"]["window"]["not_after"] = (datetime.now(UTC) - timedelta(seconds=1)).strftime(FMT)


ROWS: list[tuple[str, Callable[[dict[str, Any]], None], str, list[str] | None]] = [
    ("confirmed false", S(["authorization", "confirmed"], False), "AUTH_NOT_CONFIRMED", None),
    ("empty allow", S(["scope", "allow"], []), "SCOPE_EMPTY", None),
    ("outside allow", S(["targets", "domains"], ["other.lab.test"]), "TARGET_NOT_IN_SCOPE", None),
    ("on deny", S(["scope", "deny"], ["target.lab.test"]), "TARGET_DENIED", None),
    ("metadata allowed", _meta_allowed, "TARGET_DENIED", None),
    ("metadata not allowed", S(["targets", "domains"], ["169.254.169.254"]), "TARGET_DENIED", None),
    ("rate above", S(["scope", "rate_limit_rps"], 10.0001), "RATE_ABOVE_CEILING", None),
    ("window missing", _del_window, "WINDOW_MISSING", None),
    ("not_after missing", _del_not_after, "WINDOW_MISSING", None),
    ("expired", _expired, "WINDOW_EXPIRED", None),
    ("naive", S(["scope", "window", "not_before"], "2026-01-01T00:00:00"),
     "WINDOW_NAIVE_DATETIME", None),
    ("too long", _too_long, "WINDOW_TOO_LONG", None),
    ("secret_ref", _secret_ref, "SECRET_INLINE", None),
    ("extra root", _extra_root, "UNKNOWN_FIELD", None),
    ("extra nested", _extra_scope, "UNKNOWN_FIELD", None),
    ("two violations", _two, "AUTH_NOT_CONFIRMED", ["AUTH_NOT_CONFIRMED", "SCOPE_EMPTY"]),
]


@pytest.mark.parametrize("label,mutator,code,all_codes", ROWS, ids=[r[0] for r in ROWS])
async def test_ac6_rejection_matrix(env: Env, label: str, mutator: Callable[..., None],
                                    code: str, all_codes: list[str] | None) -> None:
    org = await env.org()
    p = valid_payload(env.clock.now())
    mutator(p)
    before = len(env.chain.entries(env.intake(org)))
    r = await env.create_engagement(org, p)
    assert r.status_code == 422, label
    assert r.headers["content-type"].startswith("application/problem+json")
    body = r.json()
    assert body["code"] == code
    assert set(body) <= PROBLEM_KEYS and "ledger_seq" in body
    entries = env.chain.entries(env.intake(org))
    assert len(entries) == before + 1
    e = entries[-1]
    assert body["ledger_seq"] == e.seq
    assert e.kind == "engagement.rejected" and e.actor == f"user:{org.key_id}"
    assert e.payload["primary"] == code and code in e.payload["codes"]  # type: ignore[operator]
    if all_codes:
        assert e.payload["codes"] == all_codes
    blob = json.dumps(dict(e.payload))
    assert "foo_canary" not in blob and "ref://A/b" not in blob
    assert not {k for k in e.payload if k.lower() in FORBIDDEN_PAYLOAD_KEYS}
    assert not [c for c in env.chain.chains if c.startswith("engagement:")]
    rows = await env.sql("SELECT count(*) AS n FROM engagements WHERE org_id=:o", o=org.org_id)
    assert rows[0]["n"] == 0


async def test_controls_that_must_succeed(env: Env) -> None:
    org = await env.org()
    p = valid_payload(env.clock.now())
    p["scope"]["rate_limit_rps"] = 10
    assert (await env.create_engagement(org, p)).status_code == 201
    q = valid_payload(env.clock.now())
    from datetime import datetime

    nb = datetime.strptime(q["scope"]["window"]["not_before"], FMT)
    q["scope"]["window"]["not_after"] = (nb + timedelta(days=90)).strftime(FMT)
    assert (await env.create_engagement(org, q)).status_code == 201


async def test_profile_not_enabled(api_db: Any) -> None:
    e = await make_env(api_db, enable_lab=False)
    try:
        org = await e.org()
        r = await e.create_engagement(org)
        assert r.status_code == 422 and r.json()["code"] == "PROFILE_NOT_ENABLED"
        assert e.chain.entries(e.intake(org))[-1].payload["primary"] == "PROFILE_NOT_ENABLED"
    finally:
        await e.close()


NOT_LEDGERED: list[tuple[str, Callable[[dict[str, Any]], None], int]] = [
    ("rate zero", S(["scope", "rate_limit_rps"], 0), 422),
    ("name type", S(["name"], 12), 422),
    ("name 256", S(["name"], "n" * 256), 422),
    ("name NUL", S(["name"], "a\u0000b"), 422),
    ("empty name", S(["name"], ""), 422),
    ("approver 201", S(["authorization", "approver"], "a" * 201), 422),
    ("statement 4097", S(["authorization", "statement"], "s" * 4097), 422),
    ("too many domains", S(["targets", "domains"], [f"d{i}.lab.test" for i in range(51)]), 422),
    ("backwards window", S(["scope", "window", "not_before"], "2099-01-01T00:00:00Z"), 422),
]


@pytest.mark.parametrize("label,mutator,status", NOT_LEDGERED, ids=[r[0] for r in NOT_LEDGERED])
async def test_generic_rejections_are_not_ledgered(env: Env, label: str,
                                                   mutator: Callable[..., None],
                                                   status: int) -> None:
    org = await env.org()
    p = valid_payload(env.clock.now())
    mutator(p)
    r = await env.create_engagement(org, p)
    assert r.status_code == status and r.json()["code"] == "INVALID_REQUEST", label
    assert "ledger_seq" not in r.json()
    assert env.chain.entries(env.intake(org)) == []
    assert not [c for c in env.chain.chains if c.startswith("engagement:")]
    assert (await env.sql("SELECT count(*) AS n FROM engagements WHERE org_id=:o",
                          o=org.org_id))[0]["n"] == 0


async def test_length_boundaries_at_the_limit_succeed(env: Env) -> None:
    org = await env.org()
    p = valid_payload(env.clock.now())
    p["name"] = "n" * 255
    p["authorization"]["approver"] = "a" * 200
    p["authorization"]["statement"] = "s" * 4096
    r = await env.create_engagement(org, p)
    assert r.status_code == 201, r.text
    created = env.chain.entries(f"engagement:{r.json()['id']}")[0]
    blob = json.dumps(dict(created.payload))
    assert "a" * 200 not in blob and "s" * 4096 not in blob  # hashes only
    assert created.payload["authorization_basis"]["approver_len"] == 200  # type: ignore[index]


async def test_over_limit_never_reaches_the_database(env: Env) -> None:
    from sqlalchemy import event

    org = await env.org()
    seen: list[str] = []

    def hook(conn, cursor, statement, params, context, executemany):  # type: ignore[no-untyped-def]
        seen.append(statement)

    event.listen(env.engine.sync_engine, "before_cursor_execute", hook)
    try:
        p = valid_payload(env.clock.now())
        p["name"] = "n" * 256
        assert (await env.create_engagement(org, p)).status_code == 422
        assert not [s for s in seen if s.lstrip().upper().startswith("INSERT INTO ENGAGEMENTS")]
    finally:
        event.remove(env.engine.sync_engine, "before_cursor_execute", hook)


async def test_success_shape_and_first_ledger_entry(env: Env) -> None:
    org = await env.org()
    p = valid_payload(env.clock.now())
    r = await env.create_engagement(org, p)
    assert r.status_code == 201
    body = r.json()
    assert set(body) == {"id", "status", "created_at", "ledger_seq"}
    assert body["status"] == "active" and body["ledger_seq"] == 0
    assert "idempotent-replayed" not in r.headers
    (e,) = env.chain.entries(f"engagement:{body['id']}")
    assert e.kind == "engagement.created" and e.actor == f"user:{org.key_id}" and e.seq == 0
    pl = dict(e.payload)
    assert pl["engagement_id"] == body["id"] and pl["rate_limit_mrps"] == 5000
    assert not {k for k in pl if k.lower() in FORBIDDEN_PAYLOAD_KEYS}
    assert "authorization_basis" in pl and pl["authorization_basis"]["confirmed"] is True  # type: ignore[index]
    assert p["authorization"]["statement"] not in json.dumps(pl)
    assert p["authorization"]["approver"] not in json.dumps(pl)

    def no_floats(v: Any) -> None:
        assert not isinstance(v, float)
        if isinstance(v, dict):
            [no_floats(x) for x in v.values()]
        if isinstance(v, list):
            [no_floats(x) for x in v]

    no_floats(pl)
    # UUIDv7 id
    assert body["id"][14] == "7"


async def test_get_engagement_view_never_exposes_secret_ref(env: Env) -> None:
    org = await env.org()
    p = valid_payload(env.clock.now())
    p["identities"] = [{"label": "a", "role": "r",
                        "auth": {"type": "bearer", "secret_ref": "ref://vault/path"}}]
    r = await env.create_engagement(org, p)
    assert r.status_code == 201
    v = (await env.get(f"/v1/engagements/{r.json()['id']}", org)).json()
    assert v["status"] == "active" and v["identities"][0]["auth"] == {"type": "bearer"}
    assert "ref://vault/path" not in json.dumps(v)
    assert v["revoked_at"] is None and v["revoked_reason"] is None


async def test_ledger_failure_on_rejection_is_503_and_nothing_replayable(env: Env) -> None:
    org = await env.org()
    p = valid_payload(env.clock.now())
    p["authorization"]["confirmed"] = False
    env.chain.fail_next_appends = 1
    r = await env.create_engagement(org, p, key="rej-key-1")
    assert r.status_code == 503 and r.json()["code"] == "UNAVAILABLE"
    assert "canary-should-never-surface" not in r.text
    r2 = await env.create_engagement(org, p, key="rej-key-1")
    assert r2.status_code == 422 and "idempotent-replayed" not in r2.headers


async def test_ledger_failure_on_create_leaves_no_row_and_releases_the_claim(env: Env) -> None:
    org = await env.org()
    p = valid_payload(env.clock.now())
    env.chain.fail_next_appends = 1
    r = await env.create_engagement(org, p, key="create-key-1")
    assert r.status_code == 503
    assert (await env.sql("SELECT count(*) AS n FROM engagements WHERE org_id=:o",
                          o=org.org_id))[0]["n"] == 0
    r2 = await env.create_engagement(org, p, key="create-key-1")
    assert r2.status_code == 201
