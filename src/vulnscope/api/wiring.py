"""Production wiring seam. In D-early there is NO production wiring: ``build_production_wiring``
refuses, so ``create_app()`` without wiring fails to start (fail closed). D-final binds
``decide_and_record``, ``PostgresChainBackend``, ``verify`` and the real clock/resolver here.
"""
from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncEngine

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


class WiringNotAvailable(RuntimeError):
    """The production wiring has not been built (D-early)."""


@dataclass(frozen=True)
class Wiring:
    chain_backend: ChainBackend
    verify_fn: VerifyFn
    checkpoint_source: CheckpointSource
    clock: Clock
    sanitize: Sanitizer
    target_checker: TargetChecker
    scan_gate: ScanGate


def build_production_wiring(settings: Settings, engine: AsyncEngine) -> Wiring:
    raise WiringNotAvailable("production wiring is not available in this build")
