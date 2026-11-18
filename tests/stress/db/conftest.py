# ruff: noqa: E501
"""tests/stress/db conftest (R1; docs/gates/slice0-grants-stress-pins.md GR-STR-20/21).

Supersedes, for this directory, tests/stress/conftest.py's "collection errors are expected"
convention: nothing here may fail at collection. Anything from vulnscope.db.migration_grants /
role_checks is imported lazily inside test bodies (guarded by test_import_guard.py).

Registers vulnscope_db_plugin (fixtures, zero-skip hook, inventory enforcement) so that it also
applies to tests/integration when both trees are in one pytest session. Does not use
requires_postgres skips: missing env URLs skip only inside the plugin's fixtures, and under
VULNSCOPE_REQUIRE_INTEGRATION=1 every such skip is converted into a failure.
"""
from __future__ import annotations

import pytest
import vulnscope_db_plugin


def pytest_configure(config: pytest.Config) -> None:
    if not config.pluginmanager.has_plugin("vulnscope_db_plugin"):
        config.pluginmanager.register(vulnscope_db_plugin, "vulnscope_db_plugin")
