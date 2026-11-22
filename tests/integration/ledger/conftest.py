"""Fixtures for the ledger integration tests (see ledger_pg_support for the database policy)."""
from __future__ import annotations

import sys
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))  # basename-unique helper, rootdir mode

from ledger_pg_support import open_backend  # noqa: E402

from vulnscope.ledger.postgres_backend import PostgresChainBackend  # noqa: E402


@pytest.fixture(scope="module")
def ledger_db(request: pytest.FixtureRequest) -> Any:
    """The plugin's fresh, migrated scratch database. A missing plugin is a FAILURE, never a skip
    (a skip would hide the missing proof, F14)."""
    try:
        return request.getfixturevalue("migrated_scratch")
    except pytest.FixtureLookupError:
        pytest.fail(
            "ledger integration tests need `-p vulnscope_db_plugin` with PYTHONPATH including "
            "tests/stress/db",
            pytrace=False,
        )


@pytest.fixture
async def backend(ledger_db: Any) -> AsyncIterator[PostgresChainBackend]:
    engine, b = await open_backend(ledger_db)
    try:
        yield b
    finally:
        await engine.dispose()
