"""Shared fakes for policy/ stress tests.

Provides factory fixtures (not direct module-level objects) for:
- a deterministic Clock fake (D6: tz-aware wall clock + monotonic),
- a Resolver fake backed by a fixed hostname -> IPs map that counts calls
  (used by the DNS-pinning-boundary tests to assert decide() resolves at
  most once per call),
- an EngagementPolicyView builder with sane defaults, per
  docs/gates/slice0-plan.md Section 3.1.

Using factory fixtures (functions/classes returned by a fixture) rather than
importing helpers via `from .conftest import ...` keeps these test files
independent of whether tests/stress/policy/ is set up as a Python package.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from vulnscope.policy.resolver import ResolutionError
from vulnscope.policy.types import EngagementPolicyView


class FixedClock:
    """Deterministic Clock fake (policy/clock.py Clock Protocol, D6).

    Wall time (`now()`) and monotonic time (`monotonic()`) advance
    independently and only when `advance()` is called explicitly -- this is
    what makes window-boundary and rate-limit stress tests reproducible.
    """

    def __init__(self, now: datetime, monotonic_start: float = 0.0) -> None:
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
    """Resolver fake (policy/resolver.py Resolver Protocol) backed by a
    fixed hostname -> IPs table. Records every call so tests can assert on
    *how many times* decide() resolved a given hostname (the DNS-pinning-
    boundary invariant: at most once per decide() call).
    """

    def __init__(self, table: dict[str, tuple[str, ...]]) -> None:
        self._table = table
        self.calls: list[str] = []

    def resolve(self, hostname: str) -> tuple[str, ...]:
        self.calls.append(hostname)
        if hostname not in self._table:
            raise ResolutionError(f"no record for {hostname!r}")
        return self._table[hostname]


def _make_engagement(**overrides: Any) -> EngagementPolicyView:
    base_window_start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    defaults: dict[str, Any] = dict(
        engagement_id="11111111-1111-7111-8111-111111111111",
        org_id="22222222-2222-7222-8222-222222222222",
        profile="standard",
        status="active",
        scope_allow=(),
        scope_deny=(),
        expected_ip_ranges=(),
        rate_limit_rps=1000.0,
        window_not_before=base_window_start,
        window_not_after=base_window_start + timedelta(days=30),
        policy_version="1.0.0+teststub",
    )
    defaults.update(overrides)
    return EngagementPolicyView(**defaults)


@pytest.fixture
def fixed_clock() -> FixedClock:
    return FixedClock(datetime(2026, 1, 15, tzinfo=timezone.utc))


@pytest.fixture
def clock_factory():
    """Returns the FixedClock class; call clock_factory(now[, monotonic_start])."""
    return FixedClock


@pytest.fixture
def resolver_factory():
    """Returns the MapResolver class; call resolver_factory({host: (ip,...)})."""
    return MapResolver


@pytest.fixture
def engagement_factory():
    """Returns a builder; call engagement_factory(scope_allow=(...), ...)."""
    return _make_engagement
