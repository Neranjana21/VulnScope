"""Helpers for the API integration tests: build the real app over a scratch DB with doubles."""
from __future__ import annotations

import dataclasses
import re
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from api_doubles import (
    FakeCheckpointSource,
    FakeClock,
    FakeScanGate,
    FakeTargetChecker,
    FakeVerify,
    MemoryChain,
    sanitize,
)
from api_payloads import FMT, valid_payload
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from vulnscope.api.auth import hash_api_key
from vulnscope.api.limits import Timeouts
from vulnscope.api.main import create_app
from vulnscope.api.startup import harden_engine
from vulnscope.api.state import AppState, build_state
from vulnscope.config import Settings
from vulnscope.db.session import get_async_engine
from vulnscope.models.api_key import ApiKey
from vulnscope.models.engagement import Engagement
from vulnscope.models.org import Org
from vulnscope.models.scan import Scan

SCRATCH = re.compile(r"^vulnscope_(stress|task[a-z])_[0-9a-f]+$")


def app_url(db: Any) -> str:
    from stress_db_secrets import reveal

    return str(reveal(db.app_url))


@dataclass
class TestOrg:
    __test__ = False
    org_id: str
    key_id: str
    token: str
    role: str = "admin"

    @property
    def h(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"}


@dataclass
class Env:
    db: Any
    engine: AsyncEngine
    sessionmaker: async_sessionmaker[AsyncSession]
    chain: MemoryChain
    clock: FakeClock
    gate: FakeScanGate
    verify: FakeVerify
    checkpoints: FakeCheckpointSource
    settings: Settings
    app: Any
    state: AppState
    client: httpx.AsyncClient
    extra_clients: list[httpx.AsyncClient] = field(default_factory=list)

    async def close(self) -> None:
        await self.client.aclose()
        for c in self.extra_clients:
            await c.aclose()
        await self.engine.dispose()

    # ---- seeding ------------------------------------------------------------------------
    async def org(self, role: str = "admin", *, org_id: str | None = None) -> TestOrg:
        oid = org_id or str(uuid.uuid4())
        async with self.sessionmaker() as s:
            if not (await s.execute(text("SELECT 1 FROM orgs WHERE id=:i"), {"i": oid})).first():
                s.add(Org(id=oid, name=f"it-org-{uuid.uuid4().hex[:8]}"))
                await s.flush()
            await s.commit()
        return await self.key(oid, role)

    async def key(self, org_id: str, role: str, *, revoked: bool = False) -> TestOrg:
        token = f"vs_test_{uuid.uuid4().hex}"
        kid = str(uuid.uuid4())
        async with self.sessionmaker() as s:
            s.add(ApiKey(id=kid, org_id=org_id, hashed_key=hash_api_key(token), role=role,
                         revoked_at=datetime.now(UTC) if revoked else None))
            await s.commit()
        return TestOrg(org_id, kid, token, role)

    async def seed_engagement(self, org: TestOrg, *, status: str = "active",
                              payload: dict[str, Any] | None = None,
                              not_before: datetime | None = None,
                              not_after: datetime | None = None,
                              revoked_at: datetime | None = None,
                              domains: list[str] | None = None,
                              ip_ranges: list[str] | None = None,
                              allow: list[str] | None = None,
                              deny: list[str] | None = None,
                              profile: str = "lab") -> str:
        p = payload or valid_payload(self.clock.now())
        if not_before is not None:
            p["scope"]["window"]["not_before"] = not_before.strftime(FMT)
        if not_after is not None:
            p["scope"]["window"]["not_after"] = not_after.strftime(FMT)
        if domains is not None:
            p["targets"]["domains"] = domains
        if ip_ranges is not None:
            p["targets"]["ip_ranges"] = ip_ranges
        if allow is not None:
            p["scope"]["allow"] = allow
        if deny is not None:
            p["scope"]["deny"] = deny
        eid = str(uuid.uuid4())
        async with self.sessionmaker() as s:
            s.add(Engagement(
                id=eid, org_id=org.org_id, name=p["name"], profile=profile, status=status,
                targets=p["targets"], scope=p["scope"], authorization=p["authorization"],
                identities=[], ownership_rules=[], asset_tags=[],
                revoked_at=revoked_at or (self.clock.now() if status == "revoked" else None),
                revoked_reason="seeded" if status == "revoked" else None))
            await s.commit()
        return eid

    async def seed_scan(self, org: TestOrg, engagement_id: str, status: str = "queued") -> str:
        sid = str(uuid.uuid4())
        async with self.sessionmaker() as s:
            s.add(Scan(id=sid, org_id=org.org_id, engagement_id=engagement_id,
                       stages=["discover"], options={"write_tests": False}, schedule=None,
                       status=status))
            await s.commit()
        return sid

    # ---- direct reads / writes ----------------------------------------------------------
    async def sql(self, stmt: str, **params: Any) -> list[Any]:
        async with self.engine.connect() as c:
            res = await c.execute(text(stmt), params)
            return list(res.mappings().all()) if res.returns_rows else []

    async def exec(self, stmt: str, **params: Any) -> None:
        async with self.engine.begin() as c:
            await c.execute(text(stmt), params)

    # ---- http ---------------------------------------------------------------------------
    async def post(self, path: str, org: TestOrg, body: Any = None, *, key: str | None = None,
                   raw: bytes | None = None,
                   headers: dict[str, str] | None = None) -> httpx.Response:
        h = dict(org.h)
        if key is not None:
            h["Idempotency-Key"] = key
        if headers:
            h.update(headers)
        if raw is not None:
            h.setdefault("Content-Type", "application/json")
            return await self.client.post(path, content=raw, headers=h)
        return await self.client.post(path, json=body, headers=h)

    async def get(self, path: str, org: TestOrg | None, **kw: Any) -> httpx.Response:
        return await self.client.get(path, headers=org.h if org else {}, **kw)

    async def create_engagement(self, org: TestOrg, payload: dict[str, Any] | None = None,
                                key: str | None = None) -> httpx.Response:
        return await self.post("/v1/engagements", org, payload or valid_payload(self.clock.now()),
                               key=key)

    def intake(self, org: TestOrg) -> str:
        return f"intake:{org.org_id}"

    def new_client(self) -> httpx.AsyncClient:
        c = httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app),
                              base_url="http://testserver")
        self.extra_clients.append(c)
        return c


async def make_env(db: Any, *, timeouts: Timeouts | None = None, enable_lab: bool = True,
                   **state_over: Any) -> Env:
    url = app_url(db)
    engine = get_async_engine(url)
    harden_engine(engine)  # the production lifespan does the same (hide_parameters)
    async with engine.connect() as c:
        name = (await c.execute(text("SELECT current_database()"))).scalar_one()
    assert SCRATCH.fullmatch(name), "refusing a database that is not a disposable scratch DB"
    sm = async_sessionmaker(engine, expire_on_commit=False)
    settings = Settings(database_url=url, enable_lab=enable_lab, lab_cidr="127.0.0.1/32")
    app = create_app(settings)
    chain = MemoryChain()
    clock = FakeClock()
    gate = FakeScanGate(chain, clock, enable_lab)
    verify = FakeVerify()
    cps = FakeCheckpointSource()
    kw: dict[str, Any] = dict(
        settings=settings, engine=engine, sessionmaker=sm, chain_backend=chain,
        verify_fn=verify, checkpoint_source=cps, clock=clock, sanitize=sanitize,
        target_checker=FakeTargetChecker(), scan_gate=gate,
        timeouts=timeouts or Timeouts(claim_poll_s=0.01, claim_wait_s=5.0))
    kw.update(state_over)
    state = build_state(**kw)
    app.state.d = state
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                               base_url="http://testserver")
    return Env(db, engine, sm, chain, clock, gate, verify, cps, settings, app, state, client)


def future(env: Env, **kw: float) -> datetime:
    return env.clock.now() + timedelta(**kw)


__all__ = ["Env", "TestOrg", "make_env", "future", "dataclasses"]
