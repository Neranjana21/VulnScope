"""Unit tests for ``tests/integration/_guard.py``'s pure validation
functions. Deliberately under ``tests/unit/`` (not ``tests/integration/``)
since these must run without a live Postgres.

The live round-trip (``fetch_database_marker`` actually querying a real
Postgres with the marker set) is NOT exercised here -- that needs a real
connection and is covered only by the integration tests themselves, once a
throwaway dev Postgres exists. This file only exercises the pure
host/port/dbname-shape check and the pure marker-value check, plus
``require_safe_dev_database_url``'s "env var unset -> skip" branch (which
also needs no I/O, since it returns before ever building an engine).
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

# tests/integration/_guard.py is a plain helper module, not part of the
# vulnscope package and not reachable via a dotted "tests.integration"
# import (this tree has no __init__.py and this change must not touch
# pyproject.toml's pythonpath) -- so it is loaded by inserting its own
# directory onto sys.path, once, here, exactly as the four integration
# test files that consume it also do.
_INTEGRATION_DIR = Path(__file__).resolve().parents[1] / "integration"
if str(_INTEGRATION_DIR) not in sys.path:
    sys.path.insert(0, str(_INTEGRATION_DIR))

from _guard import (  # noqa: E402
    UnsafeIntegrationDatabaseError,
    require_safe_dev_database_url,
    validate_database_url_shape,
    validate_marker_value,
)

ENV_VAR = "VULNSCOPE_TEST_SOME_DATABASE_URL"
GOOD_URL = "postgresql+asyncpg://vulnscope_app:secret@127.0.0.1:5432/vulnscope"


def test_validate_database_url_shape_accepts_the_expected_shape() -> None:
    # Returns normally -- no exception.
    validate_database_url_shape(ENV_VAR, GOOD_URL)


def test_validate_database_url_shape_rejects_wrong_host() -> None:
    bad_url = "postgresql+asyncpg://vulnscope_app:secret@10.0.0.5:5432/vulnscope"
    with pytest.raises(UnsafeIntegrationDatabaseError) as exc_info:
        validate_database_url_shape(ENV_VAR, bad_url)
    assert ENV_VAR in str(exc_info.value)


def test_validate_database_url_shape_rejects_localhost_specifically() -> None:
    # The owner's explicit case: "localhost" often resolves to the same
    # loopback interface as 127.0.0.1, but this guard compares the literal
    # string and never resolves DNS -- it must still be rejected.
    localhost_url = "postgresql+asyncpg://vulnscope_app:secret@localhost:5432/vulnscope"
    with pytest.raises(UnsafeIntegrationDatabaseError) as exc_info:
        validate_database_url_shape(ENV_VAR, localhost_url)
    assert "localhost" in str(exc_info.value)


def test_validate_database_url_shape_rejects_wrong_port() -> None:
    bad_url = "postgresql+asyncpg://vulnscope_app:secret@127.0.0.1:9999/vulnscope"
    with pytest.raises(UnsafeIntegrationDatabaseError):
        validate_database_url_shape(ENV_VAR, bad_url)


def test_validate_database_url_shape_rejects_wrong_database_name() -> None:
    bad_url = "postgresql+asyncpg://vulnscope_app:secret@127.0.0.1:5432/production"
    with pytest.raises(UnsafeIntegrationDatabaseError):
        validate_database_url_shape(ENV_VAR, bad_url)


def test_validate_marker_value_accepts_the_expected_marker() -> None:
    # Returns normally -- no exception.
    validate_marker_value("dev-disposable", ENV_VAR)


def test_validate_marker_value_rejects_missing_marker() -> None:
    with pytest.raises(UnsafeIntegrationDatabaseError):
        validate_marker_value(None, ENV_VAR)


@pytest.mark.parametrize("wrong_marker", ["production", "something-else", "dev-disposabl"])
def test_validate_marker_value_rejects_incorrect_marker(wrong_marker: str) -> None:
    with pytest.raises(UnsafeIntegrationDatabaseError):
        validate_marker_value(wrong_marker, ENV_VAR)


async def test_require_safe_dev_database_url_skips_when_env_var_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(ENV_VAR, raising=False)
    with pytest.raises(pytest.skip.Exception):
        await require_safe_dev_database_url(ENV_VAR)
