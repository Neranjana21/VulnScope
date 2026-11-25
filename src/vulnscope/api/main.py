"""Application factory. ``create_app(settings: Settings | None = None) -> FastAPI`` (pinned).

No parameter, environment switch or branch lets tests bypass the lifespan: the production lifespan
validates settings, builds the engine and the wiring, and refuses to start if any step fails.
Tests build the app with ``create_app(Settings(...))`` and assign ``app.state.d`` themselves.
"""
from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import replace

from fastapi import FastAPI

from vulnscope.api.limits import Timeouts
from vulnscope.api.middleware import OuterGuard
from vulnscope.api.problem import install
from vulnscope.api.routers import engagements, health, ledger, scans
from vulnscope.api.startup import (
    harden_engine,
    install_log_filters,
    start_reconciliation,
    validate_settings,
)
from vulnscope.api.state import build_state
from vulnscope.api.wiring import build_production_wiring
from vulnscope.config import Settings, load_admission_overrides
from vulnscope.db.session import get_async_engine


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings: Settings = app.state.settings
    validate_settings(settings)
    base = Timeouts()
    # invalid VULNSCOPE_API_AUTH_* values stop startup (fail closed); env is read in config.py only
    adm = load_admission_overrides({
        "auth_inflight": base.auth_inflight, "auth_reserved": base.auth_reserved,
        "auth_queue_wait_s": base.auth_queue_wait_s,
        "auth_db_budget_s": base.auth_db_budget_s})
    timeouts = replace(
        base, auth_inflight=adm.auth_inflight, auth_reserved=adm.auth_reserved,
        auth_queue_wait_s=adm.auth_queue_wait_s, auth_db_budget_s=adm.auth_db_budget_s)
    assert settings.database_url is not None
    engine = get_async_engine(settings.database_url)
    try:
        harden_engine(engine)
        wiring = build_production_wiring(settings, engine)
        from sqlalchemy.ext.asyncio import async_sessionmaker

        state = build_state(
            settings=settings, engine=engine,
            sessionmaker=async_sessionmaker(engine, expire_on_commit=False),
            chain_backend=wiring.chain_backend, verify_fn=wiring.verify_fn,
            checkpoint_source=wiring.checkpoint_source, clock=wiring.clock,
            sanitize=wiring.sanitize, target_checker=wiring.target_checker,
            scan_gate=wiring.scan_gate, timeouts=timeouts)
        install_log_filters()
        app.state.d = state
        task = start_reconciliation(state)
        try:
            yield
        finally:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
    finally:
        await engine.dispose()


def create_app(settings: Settings | None = None) -> FastAPI:
    resolved = settings if settings is not None else Settings()
    app = FastAPI(debug=False, docs_url=None, redoc_url=None, openapi_url=None,
                  lifespan=lifespan)
    app.router.redirect_slashes = False
    app.state.settings = resolved
    install(app)
    for module in (health, engagements, scans, ledger):
        app.include_router(module.router)
    app.add_middleware(OuterGuard)  # added last: outermost of the user middleware
    return app
