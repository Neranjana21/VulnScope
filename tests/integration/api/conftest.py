"""Fixtures for the API integration tests (D-early, doubles for the ledger and the policy gate).

Database policy: ONLY the R1 plugin's disposable scratch databases (``vulnscope_stress_<hex>``) are
used, through the plugin's ``migrated_scratch`` fixture. This package never reads a database
environment variable (tests/integration/api/test_integration_api_no_env_db.py enforces it), never
touches the shared dev database and never prints a URL. The app is always built from
``Settings(database_url=...)`` plus an ``AppState`` assigned by ``api_it_support.make_env``.

Run (orchestrator): ``scripts/with_task_db.py --mode scratch --task d --
pytest tests/integration/api -rs`` (the wrapper provides the plugin's two env URLs and
VULNSCOPE_REQUIRE_INTEGRATION=1).
"""
from __future__ import annotations

import sys
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

_HERE = Path(__file__).resolve().parent
for _p in (_HERE, _HERE.parents[1] / "unit" / "api", _HERE.parents[1] / "stress" / "db"):
    if str(_p) not in sys.path:  # rootdir import mode: no packages
        sys.path.insert(0, str(_p))

import vulnscope_db_plugin  # noqa: E402
from api_it_support import Env, make_env  # noqa: E402


def pytest_configure(config: pytest.Config) -> None:
    if not config.pluginmanager.has_plugin("vulnscope_db_plugin"):
        config.pluginmanager.register(vulnscope_db_plugin, "vulnscope_db_plugin")


@pytest.fixture(scope="module")
def api_db(request: pytest.FixtureRequest) -> Any:
    """A fresh, migrated scratch database per module. A missing plugin fixture is a FAILURE."""
    try:
        return request.getfixturevalue("migrated_scratch")
    except pytest.FixtureLookupError:
        pytest.fail("the vulnscope_db_plugin fixtures are not available", pytrace=False)


@pytest.fixture
async def env(api_db: Any) -> AsyncIterator[Env]:
    e = await make_env(api_db)
    try:
        yield e
    finally:
        await e.close()
