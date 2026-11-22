"""Fixtures for the ledger integration tests (see ledger_pg_support for the database policy).

The R1 plugin (``vulnscope_db_plugin``, tests/stress/db) is registered here the same way
tests/stress/db/conftest.py does it, so these tests do not depend on a ``-p`` flag or on a
PYTHONPATH that includes tests/stress/db (the wrapper pins PYTHONPATH to src). Registration opens
no connection; the plugin's fixtures decide which database is used (scratch only).
"""
from __future__ import annotations

import sys
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

_HERE = Path(__file__).resolve().parent
for _p in (_HERE, _HERE.parents[1] / "stress" / "db"):  # rootdir import mode: no packages
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import vulnscope_db_plugin  # noqa: E402
from ledger_pg_support import open_backend  # noqa: E402

from vulnscope.ledger.postgres_backend import PostgresChainBackend  # noqa: E402


def pytest_configure(config: pytest.Config) -> None:
    if not config.pluginmanager.has_plugin("vulnscope_db_plugin"):
        config.pluginmanager.register(vulnscope_db_plugin, "vulnscope_db_plugin")


@pytest.fixture(scope="module")
def ledger_db(request: pytest.FixtureRequest) -> Any:
    """The plugin's fresh, migrated scratch database. A missing plugin fixture is a FAILURE,
    never a skip (a skip would hide the missing proof, F14)."""
    try:
        return request.getfixturevalue("migrated_scratch")
    except pytest.FixtureLookupError:
        pytest.fail("the vulnscope_db_plugin fixtures are not available", pytrace=False)


@pytest.fixture
async def backend(ledger_db: Any) -> AsyncIterator[PostgresChainBackend]:
    engine, b = await open_backend(ledger_db)
    try:
        yield b
    finally:
        await engine.dispose()
