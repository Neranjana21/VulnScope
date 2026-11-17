"""Shared integration-test safety guard: an integration test may only run
against the local, disposable dev Postgres from docker-compose.dev.yml --
never an external, production, or unrelated database. Checks the URL shape
first (host/port/dbname, no I/O), then a database-level marker (requires
one round-trip query) before any destructive test proceeds.

Deliberately named ``_guard.py``, not ``conftest.py``: the rejection logic
itself (``validate_database_url_shape``/``validate_marker_value``) is pure
and unit-testable without a live Postgres (see
``tests/unit/test_integration_guard.py``), which a pytest fixture body
inside a ``conftest.py`` would make awkward to exercise directly.

Not part of the ``vulnscope`` package and not collected by pytest as a
test module (no ``test_`` prefix) -- it is a plain helper module, loaded
by the four integration-test files via an explicit ``sys.path`` insertion
of this directory (see the short header comment each of those files
carries), since this repo's ``tests/`` tree has no ``__init__.py``
anywhere and this change must not touch ``pyproject.toml``.
"""
from __future__ import annotations

import os
from urllib.parse import urlparse

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

EXPECTED_HOST = "127.0.0.1"  # exact match only -- "localhost" is deliberately rejected,
# even though it often resolves to the same loopback interface; this guard
# compares the literal string, never resolves DNS.
EXPECTED_PORT = 5432  # must match docker-compose.dev.yml's published port
EXPECTED_DB = "vulnscope"  # must match docker-compose.dev.yml's POSTGRES_DB
EXPECTED_MARKER = "dev-disposable"


class UnsafeIntegrationDatabaseError(RuntimeError):
    """Raised when a configured integration-test database URL does not
    point at the expected local disposable dev database, or fails the
    marker check. This is the testable unit -- fixtures convert it to
    ``pytest.fail()``.
    """


def validate_database_url_shape(env_var: str, url: str) -> None:
    """Pure, no I/O. Raises ``UnsafeIntegrationDatabaseError`` on any
    mismatch."""
    parsed = urlparse(url)
    if parsed.hostname != EXPECTED_HOST:
        raise UnsafeIntegrationDatabaseError(
            f"{env_var}: host {parsed.hostname!r} != {EXPECTED_HOST!r} -- only the exact "
            f"loopback literal {EXPECTED_HOST!r} is accepted; 'localhost' and every other "
            f"host are rejected on purpose."
        )
    if parsed.port != EXPECTED_PORT:
        raise UnsafeIntegrationDatabaseError(
            f"{env_var}: port {parsed.port!r} != {EXPECTED_PORT!r}"
        )
    dbname = (parsed.path or "").lstrip("/")
    if dbname != EXPECTED_DB:
        raise UnsafeIntegrationDatabaseError(
            f"{env_var}: database name {dbname!r} != {EXPECTED_DB!r}"
        )


def validate_marker_value(marker: str | None, env_var: str) -> None:
    """Pure, no I/O -- takes an already-fetched marker value. Raises on
    missing (``None``) or incorrect marker."""
    if marker != EXPECTED_MARKER:
        raise UnsafeIntegrationDatabaseError(
            f"{env_var}: database-level marker vulnscope.env={marker!r} != "
            f"{EXPECTED_MARKER!r} -- refusing to run destructive integration tests "
            f"against a database that isn't marked dev-disposable."
        )


async def fetch_database_marker(engine: AsyncEngine) -> str | None:
    """The one piece of actual I/O: a read-only query, nothing else,
    before any destructive test is allowed to proceed."""
    async with engine.connect() as conn:
        result = await conn.execute(text("SELECT current_setting('vulnscope.env', true)"))
        return result.scalar_one_or_none()


async def require_safe_dev_database_url(env_var: str) -> str:
    """The one function every integration-test fixture should call. Skips
    cleanly if ``env_var`` is unset (no DB configured this session);
    hard-fails (``pytest.fail``, not skip) if it's set but wrong -- a
    wrong-but-set URL is a real misconfiguration, not an absence to
    silently tolerate.
    """
    from vulnscope.db.session import get_async_engine  # local import: keep this module import-light

    url = os.environ.get(env_var)
    if not url:
        pytest.skip(
            f"{env_var} not set; this test needs a throwaway, local dev Postgres "
            f"(see docker-compose.dev.yml) -- not started this session."
        )
    try:
        validate_database_url_shape(env_var, url)
        engine = get_async_engine(url)
        try:
            marker = await fetch_database_marker(engine)
        finally:
            await engine.dispose()
        validate_marker_value(marker, env_var)
    except UnsafeIntegrationDatabaseError as exc:
        pytest.fail(str(exc))
    return url
