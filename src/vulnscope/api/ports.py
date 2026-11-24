"""Protocols and small value types the API depends on. The production implementations are bound in
``wiring.py`` (D-final); tests bind doubles. Nothing here imports ``policy/`` or a ledger
backend."""
from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

from vulnscope.ledger.chain import ChainBackend
from vulnscope.ledger.types import Checkpoint, VerifyResult

Sanitizer = Callable[[Mapping[str, object]], dict[str, object]]


class Clock(Protocol):
    def now(self) -> datetime: ...

    def monotonic(self) -> float: ...


@dataclass(frozen=True)
class EngagementSnapshot:
    """A detached, immutable view of an engagement row (no ORM object leaves ``scoping.py``)."""

    id: str
    org_id: str
    name: str
    profile: str
    status: str
    targets: Mapping[str, Any]
    scope: Mapping[str, Any]
    authorization: Mapping[str, Any]
    identities: Sequence[Any]
    ownership_rules: Sequence[Any]
    asset_tags: Sequence[Any]
    created_at: datetime
    revoked_at: datetime | None
    revoked_reason: str | None


@dataclass(frozen=True)
class TargetFinding:
    index: int
    kind: str  # "domain" | "range" | "openapi"
    code: str  # "TARGET_DENIED" | "TARGET_NOT_IN_SCOPE"
    rule: str  # fixed vocabulary, never raw input


class TargetChecker(Protocol):
    """Pure, string-level coverage and deny matching (no resolver, no clock, no I/O)."""

    def check(
        self,
        *,
        domains: Sequence[str],
        ip_ranges: Sequence[str],
        openapi_url: str | None,
        allow: Sequence[str],
        deny: Sequence[str],
        expected: Sequence[str],
        profile: str,
        lab_enabled: bool,
        lab_cidr: str | None,
    ) -> list[TargetFinding]: ...


@dataclass(frozen=True)
class GateVerdict:
    allowed: bool
    rule_id: str
    ledger_seq: int | None


class ScanGate(Protocol):
    """One policy decision per call. The implementation records the decision on the engagement
    chain (rule 8) and returns its ledger seq."""

    async def check(
        self, *, engagement: EngagementSnapshot, target: str, adapter: str, actor: str
    ) -> GateVerdict: ...


class VerifyFn(Protocol):
    async def __call__(
        self, chain_id: str, backend: ChainBackend, checkpoint: Checkpoint | None = None
    ) -> VerifyResult: ...


class CheckpointSource(Protocol):
    async def latest_valid(self, chain_id: str) -> Checkpoint | None: ...
