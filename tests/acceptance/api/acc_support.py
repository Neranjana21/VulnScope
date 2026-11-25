"""Support code for the Task D acceptance tests (design section 12.4 and PD-18).

Owner: stress-tester (R1: read-only for the implementer). Run through the wrapper in TASK mode:
``scripts/with_task_db.py --mode task --task d -- pytest tests/acceptance/api -rfE``.

Two ways to obtain an application:

* REAL (default): ``create_app(Settings(...))`` driven by ``with TestClient(app)``, so the REAL
  lifespan and the REAL production wiring (``wiring.build_production_wiring``) run. In D-early that
  function refuses (WiringNotAvailable), so every test that needs it is RED with that stated reason
  (see ``expected_red.txt``) and turns green when D-final binds the real policy and ledger.
* DRY-RUN (only when ``VULNSCOPE_ACCEPT_DRYRUN_DOUBLES=1``): the same real lifespan, but the wiring
  seam is replaced by the D-early test doubles. This exists ONLY so the stress-tester can check that
  the test code itself is coherent before D-final exists. A dry-run result is never gate evidence.

Nothing here prints an environment value, a DSN or a token. Failure messages are fixed text.
"""
from __future__ import annotations

import asyncio
import json
import sys
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
for _p in (_HERE.parents[1] / "stress", _HERE.parents[1] / "unit" / "api"):
    if str(_p) not in sys.path:  # rootdir import mode: no packages
        sys.path.insert(0, str(_p))

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import text  # noqa: E402
from sqlalchemy.ext.asyncio import create_async_engine  # noqa: E402
from sqlalchemy.pool import NullPool  # noqa: E402

from vulnscope.api.auth import hash_api_key  # noqa: E402
from vulnscope.api.main import create_app  # noqa: E402
from vulnscope.config import Settings  # noqa: E402
from vulnscope.models.api_key import ApiKey  # noqa: E402
from vulnscope.models.engagement import Engagement  # noqa: E402
from vulnscope.models.org import Org  # noqa: E402
from vulnscope.models.scan import Scan  # noqa: E402

FMT = "%Y-%m-%dT%H:%M:%SZ"
DRYRUN = False  # set by conftest from the ini option accept_dryrun (-o accept_dryrun=1)
# R1 scan payload (PD-18): the wire contract, there is no R1 fixture for it.
SCAN_PAYLOAD: dict[str, Any] = {
    "schema_version": 1,
    "stages": ["discover", "detect", "validate", "path"],
    "options": {"write_tests": False},
    "schedule": None,
}
PROBLEM_KEYS = {"type", "title", "status", "detail", "instance", "code", "request_id"}


def engagement_payload(now: datetime | None = None) -> dict[str, Any]:
    """Payload B0, shaped like the R1 ``engagement_payload_factory`` (profile lab)."""
    now = now or datetime.now(UTC)
    return {
        "schema_version": 1,
        "name": f"accept-engagement-{uuid.uuid4().hex[:12]}",
        "profile": "lab",
        "targets": {"domains": ["target.lab.test"], "ip_ranges": [], "openapi_url": None},
        "scope": {
            "allow": ["target.lab.test"], "deny": [], "expected_ip_ranges": [],
            "rate_limit_rps": 5,
            "window": {"not_before": (now - timedelta(minutes=1)).strftime(FMT),
                       "not_after": (now + timedelta(days=7)).strftime(FMT)},
        },
        "authorization": {"confirmed": True,
                          "statement": "Acceptance-test lab engagement, synthetic target only.",
                          "approver": "accept-tester"},
        "identities": [], "ownership_rules": [], "asset_tags": [],
    }


@dataclass
class Actor:
    org_id: str
    key_id: str
    token: str
    role: str = "admin"

    @property
    def h(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"}

    @property
    def intake(self) -> str:
        return f"intake:{self.org_id}"


@dataclass(repr=False)
class World:
    client: TestClient
    url: str  # a DSN: never part of any repr (pytest prints locals of failing tests)
    app: Any
    memory_chain: Any = None  # dry-run only
    extra: list[Any] = field(default_factory=list)

    def __repr__(self) -> str:
        return "World()"

    # ---- database (channel 3: the app-role connection from VULNSCOPE_TEST_DATABASE_URL) -------
    def run(self, fn: Callable[[Any], Awaitable[Any]]) -> Any:
        async def go() -> Any:
            engine = create_async_engine(self.url, poolclass=NullPool)
            try:
                return await fn(engine)
            finally:
                await engine.dispose()

        return asyncio.run(go())

    def sql(self, stmt: str, **params: Any) -> list[dict[str, Any]]:
        async def q(engine: Any) -> list[dict[str, Any]]:
            async with engine.connect() as c:
                res = await c.execute(text(stmt), params)
                return [dict(r) for r in res.mappings().all()] if res.returns_rows else []

        out: list[dict[str, Any]] = self.run(q)
        return out

    def count(self, stmt: str, **params: Any) -> int:
        return int(self.sql(stmt, **params)[0]["n"])

    def ledger_rows(self, chain_id: str) -> list[dict[str, Any]]:
        """seq, kind, actor, payload of one chain, ordered by seq."""
        if DRYRUN:
            return [{"seq": e.seq, "kind": e.kind, "actor": e.actor, "payload": dict(e.payload)}
                    for e in self.memory_chain.chains.get(chain_id, [])]
        rows = self.sql("SELECT seq, kind, actor, payload FROM ledger_entries "
                        "WHERE chain_id = :c ORDER BY seq", c=chain_id)
        for r in rows:
            if isinstance(r["payload"], str):
                r["payload"] = json.loads(r["payload"])
        return rows

    def engagement_entries_by(self, actor: "Actor") -> int:
        """Ledger entries this key wrote on any engagement:* chain. Startup reconciliation writes as
        'system' (and runs once per app start), so a global chain count would race with it."""
        who = f"user:{actor.key_id}"
        if DRYRUN:
            return sum(1 for c, es in self.memory_chain.chains.items()
                       if c.startswith("engagement:") for e in es if e.actor == who)
        return self.count("SELECT count(*) AS n FROM ledger_entries WHERE actor = :a "
                          "AND chain_id LIKE 'engagement:%'", a=who)

    def engagements_of(self, org_id: str) -> int:
        return self.count("SELECT count(*) AS n FROM engagements WHERE org_id = :o", o=org_id)

    def idem_rows(self, org_id: str) -> int:
        return self.count("SELECT count(*) AS n FROM idempotency_keys WHERE org_id = :o", o=org_id)

    # ---- seeding (ORM, bypassing the API, like the R1 admin_api_key fixture) -------------------
    def org(self, role: str = "admin") -> Actor:
        oid = str(uuid.uuid4())

        self._orm_add(Org(id=oid, name=f"accept-org-{uuid.uuid4().hex[:8]}"))
        return self.key(oid, role)

    def key(self, org_id: str, role: str, *, revoked: bool = False) -> Actor:
        token = f"vs_test_{uuid.uuid4().hex}"
        kid = str(uuid.uuid4())
        self._orm_add(ApiKey(id=kid, org_id=org_id, hashed_key=hash_api_key(token), role=role,
                             revoked_at=datetime.now(UTC) if revoked else None))
        return Actor(org_id, kid, token, role)

    def _orm_add(self, obj: Any) -> None:
        from sqlalchemy.ext.asyncio import AsyncSession

        async def add(engine: Any) -> None:
            async with AsyncSession(engine, expire_on_commit=False) as s:
                s.add(obj)
                await s.commit()

        self.run(add)

    def seed_engagement(self, actor: Actor, *, status: str = "active",
                        not_before: datetime | None = None, not_after: datetime | None = None,
                        domains: list[str] | None = None, allow: list[str] | None = None,
                        deny: list[str] | None = None, profile: str = "lab") -> str:
        p = engagement_payload()
        if not_before is not None:
            p["scope"]["window"]["not_before"] = not_before.strftime(FMT)
        if not_after is not None:
            p["scope"]["window"]["not_after"] = not_after.strftime(FMT)
        if domains is not None:
            p["targets"]["domains"] = domains
        if allow is not None:
            p["scope"]["allow"] = allow
        if deny is not None:
            p["scope"]["deny"] = deny
        eid = str(uuid.uuid4())
        self._orm_add(Engagement(
            id=eid, org_id=actor.org_id, name=p["name"], profile=profile, status=status,
            targets=p["targets"], scope=p["scope"], authorization=p["authorization"],
            identities=[], ownership_rules=[], asset_tags=[],
            revoked_at=datetime.now(UTC) if status == "revoked" else None,
            revoked_reason="seeded" if status == "revoked" else None))
        return eid

    def seed_scan(self, actor: Actor, eid: str, status: str = "queued") -> str:
        sid = str(uuid.uuid4())
        self._orm_add(Scan(id=sid, org_id=actor.org_id, engagement_id=eid, stages=["discover"],
                           options={"write_tests": False}, schedule=None, status=status))
        return sid

    # ---- HTTP ---------------------------------------------------------------------------------
    def post(self, path: str, actor: Actor | None, body: Any = None, *, key: str | None = None,
             raw: bytes | Any = None, headers: dict[str, str] | None = None,
             client: TestClient | None = None) -> Any:
        h = dict(actor.h) if actor else {}
        if key is not None:
            h["Idempotency-Key"] = key
        if headers:
            h.update(headers)
        c = client or self.client
        if raw is not None:
            h.setdefault("Content-Type", "application/json")
            return c.post(path, content=raw, headers=h)
        return c.post(path, json=body, headers=h)

    def get(self, path: str, actor: Actor | None, **kw: Any) -> Any:
        return self.client.get(path, headers=actor.h if actor else {}, **kw)

    def create(self, actor: Actor, payload: dict[str, Any] | None = None,
               key: str | None = None) -> Any:
        return self.post("/v1/engagements", actor, payload or engagement_payload(), key=key)

    def verify(self, actor: Actor, chain: str) -> Any:
        return self.get("/v1/ledger/verify", actor, params={"chain": chain})


def assert_problem(resp: Any, status: int, code: str) -> dict[str, Any]:
    """Wire shape of every error (PD-18): problem+json, the seven keys, X-Request-ID."""
    ok = (resp.status_code == status
          and resp.headers.get("content-type", "").split(";")[0] == "application/problem+json"
          and "x-request-id" in resp.headers)
    body = resp.json()
    ok = ok and PROBLEM_KEYS <= set(body) and set(body) <= PROBLEM_KEYS | {"ledger_seq"}
    ok = ok and body.get("code") == code and body.get("status") == status
    if not ok:  # fixed text: the response may echo nothing secret, but never format it anyway
        raise AssertionError(f"problem response shape or code mismatch (expected {status} {code})")
    out: dict[str, Any] = body
    return out


def strip_volatile(body: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in body.items() if k not in ("instance", "request_id")}


def build_world(url: str, *, enable_lab: bool = True) -> Any:
    """Context manager factory is in conftest; this builds the app only."""
    settings = Settings(database_url=url, enable_lab=enable_lab, lab_cidr="127.0.0.1/32")
    return create_app(settings)
