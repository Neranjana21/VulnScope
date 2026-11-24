"""Startup duties: settings validation (fail closed), engine hardening, log scrubbing and the
reconciliation task (design PD-03, PD-04 item 7, PD-07). No branch here depends on a test."""
from __future__ import annotations

import asyncio
import logging
import math

from sqlalchemy.ext.asyncio import AsyncEngine

from vulnscope.api.logging import ScrubFilter
from vulnscope.api.revoke_recorder import reconcile_revokes
from vulnscope.api.state import AppState
from vulnscope.config import Settings


class ConfigError(RuntimeError):
    """A fixed-text configuration refusal (never contains a value)."""


def validate_settings(settings: Settings) -> None:
    if not settings.database_url:
        raise ConfigError("database_url is not set")
    if not math.isfinite(settings.max_rps_per_host) or settings.max_rps_per_host <= 0:
        raise ConfigError("max_rps_per_host must be finite and positive")
    if not (1 <= settings.max_window_days <= 3650):
        raise ConfigError("max_window_days must be between 1 and 3650")


def harden_engine(engine: AsyncEngine) -> None:
    """Hide statement parameters in SQLAlchemy exception text (a stored value or a key hash must
    never reach a log). ``db/session.py`` is frozen, so the attribute is set after construction;
    a test proves it is honoured."""
    engine.sync_engine.hide_parameters = True


_SCRUBBED = ("", "uvicorn", "uvicorn.error", "uvicorn.access", "sqlalchemy")
_QUIET = ("sqlalchemy.engine", "sqlalchemy.pool", "asyncpg", "uvicorn.error")


def install_log_filters() -> None:
    """Attach the scrub filter to every handler present now and quiet chatty third parties.
    Handlers added later are not covered: the real control is that no raw exception is logged."""
    scrub = ScrubFilter()
    for name in _SCRUBBED:
        for handler in logging.getLogger(name).handlers:
            if not any(isinstance(f, ScrubFilter) for f in handler.filters):
                handler.addFilter(scrub)
    for name in _QUIET:
        logging.getLogger(name).setLevel(logging.WARNING)


def start_reconciliation(state: AppState) -> asyncio.Task[None]:
    async def run() -> None:
        try:
            await reconcile_revokes(state)
        except Exception:  # noqa: BLE001 - best effort; the next start retries
            from vulnscope.api.logging import log_event

            log_event("revoke_repair_failed", reason="reconcile_task")

    return asyncio.create_task(run())
