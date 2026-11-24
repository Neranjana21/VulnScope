"""``AppState``: everything a request handler needs, built by the lifespan (production wiring) or by
a test helper that assigns ``app.state.d`` directly. No module-level mutable state."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from vulnscope.api.admission import Gates, build_gates
from vulnscope.api.limits import Timeouts
from vulnscope.api.logging import Coalescer
from vulnscope.api.ports import (
    CheckpointSource,
    Clock,
    Sanitizer,
    ScanGate,
    TargetChecker,
    VerifyFn,
)
from vulnscope.config import Settings
from vulnscope.ledger.chain import ChainBackend


@dataclass(frozen=True)
class AppState:
    settings: Settings
    engine: AsyncEngine
    sessionmaker: async_sessionmaker[AsyncSession]
    chain_backend: ChainBackend
    verify_fn: VerifyFn
    checkpoint_source: CheckpointSource
    clock: Clock
    sanitize: Sanitizer
    target_checker: TargetChecker
    scan_gate: ScanGate
    timeouts: Timeouts
    gates: Gates
    counters: Counter[str] = field(default_factory=Counter)
    auth_log: Coalescer = field(default_factory=Coalescer)


def build_state(
    *,
    settings: Settings,
    engine: AsyncEngine,
    sessionmaker: async_sessionmaker[AsyncSession],
    chain_backend: ChainBackend,
    verify_fn: VerifyFn,
    checkpoint_source: CheckpointSource,
    clock: Clock,
    sanitize: Sanitizer,
    target_checker: TargetChecker,
    scan_gate: ScanGate,
    timeouts: Timeouts | None = None,
) -> AppState:
    t = timeouts or Timeouts()
    return AppState(
        settings=settings, engine=engine, sessionmaker=sessionmaker, chain_backend=chain_backend,
        verify_fn=verify_fn, checkpoint_source=checkpoint_source, clock=clock, sanitize=sanitize,
        target_checker=target_checker, scan_gate=scan_gate, timeouts=t, gates=build_gates(t))
