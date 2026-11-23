"""Helpers for the ledger PostgreSQL integration tests.

Database selection (design F14): ONLY the R1 plugin's disposable scratch databases
(``vulnscope_stress_<hex>``, fresh and migrated) are used, through the plugin's ``migrated_scratch``
fixture; this package never reads a database environment variable, never touches the shared dev
database and never prints or logs a URL. Every engine asserts ``current_database()`` first.

Run (orchestrator, through the wrapper; the plugin needs tests/stress/db on the path):
    python3 scripts/with_task_db.py --mode scratch --task b -- \
        env PYTHONPATH=<worktree>/src:<worktree>/tests/stress/db VULNSCOPE_REQUIRE_INTEGRATION=1 \
        pytest -p vulnscope_db_plugin -m integration tests/integration/ledger -rs
"""
from __future__ import annotations

import re
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from vulnscope.db.session import get_async_engine
from vulnscope.ledger.postgres_backend import PostgresChainBackend

SCRATCH_NAME = re.compile(r"^vulnscope_(stress|taskb)_[0-9a-f]+$")


def app_url(db: Any) -> str:
    from stress_db_secrets import reveal

    return reveal(db.app_url)


def admin_dsn(db: Any) -> str:
    from stress_db_secrets import reveal

    return reveal(db.admin_dsn)


async def assert_scratch_database(engine: AsyncEngine) -> None:
    async with engine.connect() as conn:
        name = (await conn.execute(text("SELECT current_database()"))).scalar_one()
    assert SCRATCH_NAME.fullmatch(name), "refusing a database that is not a disposable scratch DB"


async def open_backend(db: Any, **kwargs: Any) -> tuple[AsyncEngine, PostgresChainBackend]:
    """A fresh engine and backend bound to the CURRENT event loop (asyncpg is loop-affine)."""
    engine = get_async_engine(app_url(db))
    await assert_scratch_database(engine)
    return engine, PostgresChainBackend(engine, **kwargs)


def admin_fetch(db: Any, sql: str, *args: Any) -> list[Any]:
    import vulnscope_db_plugin as plug

    return plug.fetch(admin_dsn(db), sql, *args)


def admin_exec(db: Any, *statements: str) -> None:
    import vulnscope_db_plugin as plug

    plug.execute(admin_dsn(db), *statements)


def sql_lit(s: str) -> str:
    """Quote a TEST-CONTROLLED literal (ids, hex) for the admin helper."""
    return "'" + s.replace("'", "''") + "'"
