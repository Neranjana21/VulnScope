"""Lifespan wiring with a monkeypatched wiring factory (the only seam: no branch in src), startup
reconciliation, and the static guard that no API test reads a database env var (PD-17)."""
from __future__ import annotations

import asyncio
import re
import time
from pathlib import Path

import pytest
from api_doubles import sanitize
from api_it_support import Env
from fastapi.testclient import TestClient

from vulnscope.api import main
from vulnscope.api.wiring import Wiring
from vulnscope.config import Settings

HERE = Path(__file__).resolve().parent


def test_no_api_integration_test_reads_the_environment() -> None:
    for p in sorted(HERE.glob("*.py")):
        if p.name == Path(__file__).name:
            continue
        text = p.read_text(encoding="utf-8")
        assert "os.environ" not in text and "getenv" not in text, p.name
        assert not re.search(r"VULNSCOPE_\w*DATABASE_URL", text), p.name


def test_app_never_reads_env_for_db(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VULNSCOPE_DATABASE_URL", "postgresql+asyncpg://x:y@127.0.0.1:1/other")
    app = main.create_app(Settings(database_url="postgresql+asyncpg://u:p@127.0.0.1:1/mine"))
    assert app.state.settings.database_url.endswith("/mine")


@pytest.mark.integration
async def test_lifespan_wires_state_and_reconciles_unrecorded_revokes(
        env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    org = await env.org()
    eid = await env.seed_engagement(org, status="revoked")
    wiring = Wiring(chain_backend=env.chain, verify_fn=env.verify,
                    checkpoint_source=env.checkpoints, clock=env.clock, sanitize=sanitize,
                    target_checker=env.state.target_checker, scan_gate=env.gate)
    monkeypatch.setattr(main, "build_production_wiring", lambda settings, engine: wiring)
    app = main.create_app(env.settings)

    def run() -> None:
        with TestClient(app) as c:
            assert c.get("/healthz").status_code == 200
            assert app.state.d.chain_backend is env.chain
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and not env.chain.entries(
                    f"engagement:{eid}", "engagement.revoked"):
                time.sleep(0.05)

    await asyncio.to_thread(run)
    (e,) = env.chain.entries(f"engagement:{eid}", "engagement.revoked")
    assert e.actor == "system" and dict(e.payload)["repaired"] is True


@pytest.mark.integration
async def test_admission_env_reaches_the_gates(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VULNSCOPE_API_AUTH_INFLIGHT", "9")
    monkeypatch.setenv("VULNSCOPE_API_AUTH_QUEUE_WAIT_S", "3.5")
    wiring = Wiring(chain_backend=env.chain, verify_fn=env.verify,
                    checkpoint_source=env.checkpoints, clock=env.clock, sanitize=sanitize,
                    target_checker=env.state.target_checker, scan_gate=env.gate)
    monkeypatch.setattr(main, "build_production_wiring", lambda settings, engine: wiring)
    app = main.create_app(env.settings)

    def run() -> tuple[int, float, int]:
        with TestClient(app) as c:
            assert c.get("/healthz").status_code == 200
            t = app.state.d.timeouts
            return t.auth_inflight, t.auth_queue_wait_s, t.auth_reserved

    assert await asyncio.to_thread(run) == (9, 3.5, 2)
