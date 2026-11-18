"""Async SQLAlchemy engine/session factories.

Pinned signatures (docs/gates/slice0-plan.md Section 3.7/3.8, corrected for
the approved ``asyncpg`` driver): ``get_async_engine(database_url: str) ->
AsyncEngine`` and ``get_async_sessionmaker(database_url: str) ->
async_sessionmaker[AsyncSession]``. Both take the URL explicitly rather
than reading it from the environment themselves -- ``config.py`` (the app)
and ``alembic/env.py`` (migrations, via a *different* env var and DB role,
see Section 3.8) each own their own URL sourcing. Neither function keeps
any module-level mutable state (CLAUDE.md "no global state"): every call
builds a fresh engine.
"""
from __future__ import annotations

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)


def get_async_engine(database_url: str) -> AsyncEngine:
    """Build a new AsyncEngine for ``database_url``.

    A plain (non-``async``) factory function: constructing an
    ``AsyncEngine`` does not itself require a running event loop --
    only later using it to run a query does.
    """
    return create_async_engine(database_url, pool_pre_ping=True)


def get_async_sessionmaker(database_url: str) -> async_sessionmaker[AsyncSession]:
    """Build a new async session factory bound to a fresh engine for
    ``database_url``."""
    engine = get_async_engine(database_url)
    return async_sessionmaker(engine, expire_on_commit=False)
