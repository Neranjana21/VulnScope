"""Fixtures for the Task D acceptance tests. See ``acc_support`` for the two application modes.

No skip anywhere (owner rule): a missing or wrong database is a FAILURE with fixed text, through the
R1 guard ``stress_dbguard.require_task_database_url`` (VULNSCOPE_REQUIRE_INTEGRATION=1 makes even an
unset variable a failure; a database that is not a disposable ``vulnscope_task<x>_<8 hex>`` on
127.0.0.1:5432 is refused).
"""
from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
import acc_support
from acc_support import World, build_world
from fastapi.testclient import TestClient
from stress_dbguard import require_task_database_url


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addini("accept_dryrun", "1 = replace the wiring seam with test doubles (self-check only)",
                  default="0")


def pytest_configure(config: pytest.Config) -> None:
    acc_support.DRYRUN = config.getini("accept_dryrun") == "1"
    config.addinivalue_line("markers", "acceptance: Task D wire-contract acceptance test")
    config.addinivalue_line(
        "markers", "covers_code(*codes): reason codes this acceptance case asserts on the wire")


class _OpaqueUrl(str):
    """A DSN whose repr is fixed text: pytest prints fixture values in failure reports."""

    def __repr__(self) -> str:
        return "<task database url>"


@pytest.fixture
def task_url() -> str:
    return _OpaqueUrl(require_task_database_url())


def _install_dryrun_wiring(monkeypatch: pytest.MonkeyPatch) -> Any:
    """DRY-RUN ONLY (-o accept_dryrun=1): replace the wiring seam with doubles."""
    from api_doubles import (
        FakeCheckpointSource,
        FakeScanGate,
        FakeTargetChecker,
        FakeVerify,
        MemoryChain,
        RealClock,
        sanitize,
    )

    from vulnscope.api import main
    from vulnscope.api.wiring import Wiring

    chain = MemoryChain()
    clock = RealClock()

    def fake_build(settings: Any, engine: Any) -> Wiring:
        return Wiring(chain_backend=chain, verify_fn=FakeVerify(),
                      checkpoint_source=FakeCheckpointSource(), clock=clock, sanitize=sanitize,
                      target_checker=FakeTargetChecker(),
                      scan_gate=FakeScanGate(chain, clock, settings.enable_lab))

    monkeypatch.setattr(main, "build_production_wiring", fake_build)
    return chain


@pytest.fixture
def world(task_url: str, monkeypatch: pytest.MonkeyPatch) -> Iterator[World]:
    chain = _install_dryrun_wiring(monkeypatch) if acc_support.DRYRUN else None
    app = build_world(task_url, enable_lab=True)
    with TestClient(app) as client:  # the REAL lifespan: validate, wire, self-check, reconcile
        yield World(client=client, url=task_url, app=app, memory_chain=chain)


@pytest.fixture
def world_nolab(task_url: str, monkeypatch: pytest.MonkeyPatch) -> Iterator[World]:
    chain = _install_dryrun_wiring(monkeypatch) if acc_support.DRYRUN else None
    app = build_world(task_url, enable_lab=False)
    with TestClient(app) as client:
        yield World(client=client, url=task_url, app=app, memory_chain=chain)
