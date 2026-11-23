"""STR-A3 / SEC-A21: R1 conftest constructor shape, view validation, frozen types."""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime, timedelta, tzinfo

import pytest
from policy_test_support import WINDOW_END, WINDOW_START, make_view

from vulnscope.policy.ratelimit import InMemoryRateLimitStore
from vulnscope.policy.resolver import ResolutionError
from vulnscope.policy.scope import ScopeEntryError
from vulnscope.policy.types import (
    Action,
    AuthorizationBasis,
    EngagementPolicyView,
    PolicyDecision,
    RuleId,
)

R1_FIELDS = (
    "engagement_id",
    "org_id",
    "profile",
    "status",
    "scope_allow",
    "scope_deny",
    "expected_ip_ranges",
    "rate_limit_rps",
    "window_not_before",
    "window_not_after",
    "policy_version",
)


def test_r1_conftest_constructor_with_exactly_the_11_fields() -> None:
    view = EngagementPolicyView(
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
    assert view.authorization_basis is None
    names = [f.name for f in dataclasses.fields(EngagementPolicyView) if f.init]
    assert tuple(names[:11]) == R1_FIELDS
    assert names[11:] == ["authorization_basis"]
    assert InMemoryRateLimitStore() is not None
    assert issubclass(ResolutionError, Exception)


def test_view_is_frozen_and_hashless_of_compiled_state() -> None:
    v = make_view()
    with pytest.raises(dataclasses.FrozenInstanceError):
        v.status = "revoked"  # type: ignore[misc]
    assert make_view(scope_allow=("a.test",)) == make_view(scope_allow=("a.test",))
    assert "compiled" not in repr(v).lower()
    assert all(not isinstance(getattr(v, f.name), list | dict | set) for f in dataclasses.fields(v))


@pytest.mark.parametrize("eid", ["a:b", "", "x" * 65, "a b", "a/b", "é"])
def test_bad_engagement_ids_rejected(eid: str) -> None:
    with pytest.raises(ValueError):
        make_view(engagement_id=eid)


@pytest.mark.parametrize("eid", ["eng-3", "busy-eng", "x" * 64, "A_b-9"])
def test_good_engagement_ids(eid: str) -> None:
    assert make_view(engagement_id=eid).engagement_id == eid


def test_utcoffset_none_is_naive() -> None:
    class Weird(tzinfo):
        def utcoffset(self, dt: datetime | None) -> timedelta | None:
            return None

        def dst(self, dt: datetime | None) -> timedelta | None:
            return None

        def tzname(self, dt: datetime | None) -> str | None:
            return None

    with pytest.raises(ValueError):
        make_view(window_not_before=datetime(2026, 1, 1, tzinfo=Weird()))


@pytest.mark.parametrize("rps", [0.0, -1.0, float("nan"), float("inf")])
def test_bad_rate_limit_rejected(rps: float) -> None:
    with pytest.raises(ValueError):
        make_view(rate_limit_rps=rps)


def test_unknown_profile_rejected() -> None:
    with pytest.raises(ValueError):
        make_view(profile="prod")


def test_oversized_scope_lists_raise() -> None:
    with pytest.raises(ScopeEntryError):
        make_view(scope_allow=tuple(f"h{i}.test" for i in range(257)))
    with pytest.raises(ScopeEntryError):
        make_view(scope_deny=("a" * 254,))
    with pytest.raises(ScopeEntryError):
        make_view(scope_allow=("*",))
    with pytest.raises(ScopeEntryError):
        make_view(expected_ip_ranges=("lab.test",))


def test_authorization_basis_validation() -> None:
    ok = AuthorizationBasis(confirmed=True, approver="user:42", statement_sha256="a" * 64)
    assert make_view(authorization_basis=ok).authorization_basis == ok
    for kw in (
        dict(confirmed=1, approver="x", statement_sha256="a" * 64),
        dict(confirmed=True, approver="", statement_sha256="a" * 64),
        dict(confirmed=True, approver="x" * 256, statement_sha256="a" * 64),
        dict(confirmed=True, approver="x", statement_sha256="A" * 64),
        dict(confirmed=True, approver="x", statement_sha256="a" * 63),
        dict(confirmed=True, approver="x", statement_sha256="a" * 64 + "\n"),
    ):
        with pytest.raises((ValueError, TypeError)):
            AuthorizationBasis(**kw)  # type: ignore[arg-type]
    with pytest.raises(dataclasses.FrozenInstanceError):
        ok.confirmed = False  # type: ignore[misc]


def test_policy_decision_shape() -> None:
    names = [f.name for f in dataclasses.fields(PolicyDecision)]
    assert names == [
        "allowed",
        "reason",
        "rule_id",
        "policy_version",
        "action",
        "resolved_ips",
        "ts",
        "ledger_seq",
    ]
    d = PolicyDecision(
        True, "r", RuleId.ALLOW, "v", Action("http", "h", "a"), (), datetime.now(UTC)
    )
    assert d.ledger_seq is None
    assert [r.value for r in RuleId] == [
        "ALLOW",
        "DENY_ALWAYS_LIST",
        "DENY_PRIVATE_RANGE",
        "EXCLUDED",
        "OUT_OF_SCOPE",
        "EXPIRED",
        "NOT_YET_VALID",
        "REVOKED",
        "RATE",
        "RESOLVED_OUTSIDE_EXPECTED",
        "REDIRECT_DENIED",
        "RESOLUTION_FAILED",
    ]
    assert isinstance(RuleId.ALLOW, str)
