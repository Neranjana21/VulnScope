"""Shared pytest configuration for VulnScope's stress-test suite
(docs/stress-tests.md).

Files here and under tests/stress/** are authored before implementation per
docs/decisions.md R1 / docs/agent-workflow.md, and are read-only for the
implementer once written. See docs/gates/slice0-pre-stress.md for the
per-file mapping to the stress-test catalogue and the Slice 0 acceptance
criteria they support.

Until the corresponding production module (policy/, ledger/, api/) exists,
importing from `vulnscope.*` in these test files raises
ImportError/ModuleNotFoundError at collection time. That is the EXPECTED
state right now (pre-implementation), not a bug in the test.
"""
from __future__ import annotations

import pytest


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "stress: load/property/chaos/limit test from docs/stress-tests.md",
    )
    config.addinivalue_line(
        "markers",
        "slow: test that exceeds the normal CI time budget at full catalogue scale "
        "(e.g. the 1e5/1e6-record ledger scale targets)",
    )
    config.addinivalue_line(
        "markers",
        "requires_postgres: test needs VULNSCOPE_TEST_DATABASE_URL set to a "
        "reachable, throwaway Postgres instance; skipped otherwise",
    )
