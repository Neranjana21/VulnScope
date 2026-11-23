"""Shared database guard for the R1 stress fixtures that read VULNSCOPE_TEST_DATABASE_URL.

Owner decision 2026-11-19 (docs/gates/STATUS.md "owner decisions", DB guards):
  1. A database that is not a disposable task database is REFUSED (a failure, never a skip):
     host exactly 127.0.0.1, port exactly 5432, database name fullmatching
     ``vulnscope_task[a-z]*_[0-9a-f]{8}`` (what scripts/with_task_db.py creates).
  2. A skip becomes a failure when VULNSCOPE_REQUIRE_INTEGRATION=1.

This file is byte-identical in every worktree that carries it (b-ledger and d-api), so later merges
are clean. Do not edit one copy without the other.

Secret hygiene (CLAUDE.md probe rules): nothing here ever prints, formats or returns any part of
the URL in a message. Every failure message is fixed text. ``pytest.fail(..., pytrace=False)`` keeps
the fixture's locals (which hold the URL) out of the report.
"""
from __future__ import annotations

import os
import re
from typing import NoReturn
from urllib.parse import parse_qsl, urlsplit

import pytest

TEST_DATABASE_URL_ENV = "VULNSCOPE_TEST_DATABASE_URL"
REQUIRE_INTEGRATION_ENV = "VULNSCOPE_REQUIRE_INTEGRATION"

_ALLOWED_HOSTINFO = "127.0.0.1:5432"
_TASK_DB_RE = re.compile(r"vulnscope_task[a-z]*_[0-9a-f]{8}")
_SCHEME_RE = re.compile(r"postgres(?:ql)?(?:\+[a-z0-9_]+)?")
# libpq / asyncpg let a query parameter override the authority or the database name.
_OVERRIDING_QUERY_KEYS = frozenset(
    {"host", "hostaddr", "port", "dbname", "database", "service", "servicefile",
     "target_session_attrs"}
)


def integration_required() -> bool:
    return os.environ.get(REQUIRE_INTEGRATION_ENV) == "1"


def skip_or_fail(reason: str) -> NoReturn:
    """Skip, unless VULNSCOPE_REQUIRE_INTEGRATION=1, in which case fail. ``reason`` must be fixed
    text written by the caller (never derived from an environment value)."""
    if integration_required():
        pytest.fail(
            f"integration required (VULNSCOPE_REQUIRE_INTEGRATION=1): {reason}", pytrace=False
        )
    pytest.skip(reason)


def url_is_disposable_task_database(url: str) -> bool:
    """Boolean check only; never raises, never reveals the URL."""
    try:
        if not url or any(ord(c) < 33 or ord(c) == 127 for c in url) or not url.isascii():
            return False
        parts = urlsplit(url)
        if not _SCHEME_RE.fullmatch(parts.scheme):
            return False
        if parts.netloc.rpartition("@")[2] != _ALLOWED_HOSTINFO:
            return False
        name = parts.path[1:] if parts.path.startswith("/") else ""
        if "/" in name or not _TASK_DB_RE.fullmatch(name):
            return False
        keys = {k.lower() for k, _ in parse_qsl(parts.query, keep_blank_values=True)}
        return not (keys & _OVERRIDING_QUERY_KEYS)
    except ValueError:
        return False


def require_task_database_url() -> str:
    """Return VULNSCOPE_TEST_DATABASE_URL, refusing (fail) anything but a disposable task database.

    Unset: skip, or fail under VULNSCOPE_REQUIRE_INTEGRATION=1.
    """
    url = os.environ.get(TEST_DATABASE_URL_ENV)
    if not url:
        skip_or_fail(f"{TEST_DATABASE_URL_ENV} not set (run through scripts/with_task_db.py)")
    if not url_is_disposable_task_database(url):
        pytest.fail(
            f"{TEST_DATABASE_URL_ENV} refused: only 127.0.0.1:5432 and a database named "
            "vulnscope_task<letters>_<8 hex> are allowed for stress tests",
            pytrace=False,
        )
    return url
