"""Test-side fakes and builders for policy/ unit tests (task-a-design.md section 6).

Own copies of the clock / resolver fakes (the R1 conftest fixtures live in
tests/stress/policy and are not importable from here) plus ``FakeChainBackend``,
a minimal async ``ChainBackend`` that imports only ``ledger.types`` and
``ledger.chain`` (never Task B).
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

from vulnscope.ledger.types import LedgerEntry
from vulnscope.policy.decide import decide
from vulnscope.policy.ratelimit import InMemoryRateLimitStore
from vulnscope.policy.resolver import ResolutionError
from vulnscope.policy.types import Action, EngagementPolicyView, PolicyDecision

NOW = datetime(2026, 1, 15, tzinfo=UTC)
WINDOW_START = datetime(2026, 1, 1, tzinfo=UTC)
WINDOW_END = WINDOW_START + timedelta(days=30)


class FixedClock:
    def __init__(self, now: datetime = NOW, monotonic_start: float = 0.0) -> None:
        self._now = now
        self._mono = monotonic_start

    def now(self) -> datetime:
        return self._now

    def monotonic(self) -> float:
        return self._mono

    def advance(self, seconds: float) -> None:
        self._now = self._now + timedelta(seconds=seconds)
        self._mono += seconds


class MapResolver:
    """hostname -> IPs table; records every call (the 'SpyResolver')."""

    def __init__(self, table: Mapping[str, tuple[str, ...]] | None = None) -> None:
        self.table: dict[str, tuple[str, ...]] = dict(table or {})
        self.calls: list[str] = []

    def resolve(self, hostname: str) -> tuple[str, ...]:
        self.calls.append(hostname)
        if hostname not in self.table:
            raise ResolutionError("no record")
        return self.table[hostname]


class RaisingResolver:
    def __init__(self, exc: BaseException) -> None:
        self.exc = exc
        self.calls: list[str] = []

    def resolve(self, hostname: str) -> tuple[str, ...]:
        self.calls.append(hostname)
        raise self.exc


class RawResolver:
    """Returns whatever it is given (hostile resolver output)."""

    def __init__(self, value: Any) -> None:
        self.value = value
        self.calls: list[str] = []

    def resolve(self, hostname: str) -> Any:
        self.calls.append(hostname)
        return self.value


def make_view(**overrides: Any) -> EngagementPolicyView:
    defaults: dict[str, Any] = dict(
        engagement_id="11111111-1111-7111-8111-111111111111",
        org_id="22222222-2222-7222-8222-222222222222",
        profile="standard",
        status="active",
        scope_allow=(),
        scope_deny=(),
        expected_ip_ranges=(),
        rate_limit_rps=1000.0,
        window_not_before=WINDOW_START,
        window_not_after=WINDOW_END,
        policy_version="1.0.0+teststub",
    )
    defaults.update(overrides)
    return EngagementPolicyView(**defaults)


def run_decide(
    target: str,
    *,
    allow: tuple[str, ...] = (),
    deny: tuple[str, ...] = (),
    table: Mapping[str, tuple[str, ...]] | None = None,
    resolver: Any = None,
    now: datetime = NOW,
    clock: FixedClock | None = None,
    store: InMemoryRateLimitStore | None = None,
    lab_enabled: bool = False,
    lab_cidr: str | None = None,
    redirect: bool = False,
    kind: str = "http",
    **view: Any,
) -> tuple[PolicyDecision, Any]:
    """Builds a view and calls decide(); returns (decision, resolver)."""
    view.setdefault("scope_allow", allow)
    view.setdefault("scope_deny", deny)
    engagement = make_view(**view)
    res = resolver if resolver is not None else MapResolver(table)
    clk = clock or FixedClock(now)
    action = Action(kind=kind, target=target, adapter="unit", is_redirect_hop=redirect)  # type: ignore[arg-type]
    decision = decide(
        action,
        engagement,
        now,
        resolver=res,
        clock=clk,
        rate_limit_store=store or InMemoryRateLimitStore(),
        lab_enabled=lab_enabled,
        lab_cidr=lab_cidr,
    )
    return decision, res


class FakeChainBackend:
    """Async ChainBackend fake: ``appended`` list, optional ``fail_with``."""

    def __init__(self) -> None:
        self.appended: list[LedgerEntry] = []
        self.fail_with: BaseException | None = None
        self.head_fail_with: BaseException | None = None
        self.head_calls = 0

    async def append(
        self,
        chain_id: str,
        kind: str,
        actor: str,
        payload: Mapping[str, object],
        ts: datetime,
    ) -> LedgerEntry:
        if self.fail_with is not None:
            raise self.fail_with
        entry = LedgerEntry(
            schema_version=1,
            chain_id=chain_id,
            seq=len(self.appended),
            kind=kind,
            actor=actor,
            payload=payload,
            ts=ts,
            prev_hash="0" * 64,
            record_hash="1" * 64,
        )
        self.appended.append(entry)
        return entry

    async def read(  # noqa: D102
        self, chain_id: str, start_seq: int = 0, limit: int | None = None
    ) -> AsyncIterator[LedgerEntry]:
        for entry in self.appended:
            if entry.chain_id == chain_id and entry.seq >= start_seq:
                yield entry

    async def head(self, chain_id: str) -> LedgerEntry | None:
        self.head_calls += 1
        if self.head_fail_with is not None:
            raise self.head_fail_with
        mine = [e for e in self.appended if e.chain_id == chain_id]
        return mine[-1] if mine else None

    async def record_count(self, chain_id: str) -> int:
        return len([e for e in self.appended if e.chain_id == chain_id])


def with_replace(decision: PolicyDecision, **kw: Any) -> PolicyDecision:
    return replace(decision, **kw)
