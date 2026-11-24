"""validation.validate_engagement: one case per contract reason code, fixed precedence, boundaries
(design 7.1 step 2, PD-04 item 6, PD-18 AC6 table)."""
from __future__ import annotations

import math
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from api_doubles import FakeTargetChecker
from api_payloads import FMT, valid_payload

from vulnscope.api.validation import validate_engagement
from vulnscope.config import Settings
from vulnscope.models.schemas.engagement import EngagementCreateRequest

NOW = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)


def settings(**kw: Any) -> Settings:
    base: dict[str, Any] = {"database_url": None, "enable_lab": True, "lab_cidr": None,
                            "max_rps_per_host": 10.0, "max_window_days": 90}
    base.update(kw)
    return Settings(**base)


def codes(payload: dict[str, Any], **kw: Any) -> list[str]:
    req = EngagementCreateRequest.model_validate(payload)
    return [v.code for v in validate_engagement(
        req, settings=settings(**kw), now=NOW, targets=FakeTargetChecker())]


def base() -> dict[str, Any]:
    return valid_payload(NOW)


def test_valid_payload_has_no_violation() -> None:
    assert codes(base()) == []


def _set(path: list[str], value: Any) -> Callable[[dict[str, Any]], None]:
    def f(p: dict[str, Any]) -> None:
        cur = p
        for k in path[:-1]:
            cur = cur[k]
        cur[path[-1]] = value

    return f


def fmt(dt: datetime) -> str:
    return dt.strftime(FMT)


CASES: list[tuple[str, Callable[[dict[str, Any]], None], list[str]]] = [
    ("confirmed false", _set(["authorization", "confirmed"], False), ["AUTH_NOT_CONFIRMED"]),
    ("empty allow", _set(["scope", "allow"], []), ["SCOPE_EMPTY"]),
    ("no targets", lambda p: p["targets"].update(domains=[]), ["SCOPE_EMPTY"]),
    ("not in allow", _set(["targets", "domains"], ["other.lab.test"]), ["TARGET_NOT_IN_SCOPE"]),
    ("on deny", _set(["scope", "deny"], ["target.lab.test"]), ["TARGET_DENIED"]),
    ("metadata, allowed", lambda p: (p["targets"].update(domains=["169.254.169.254"]),
                                     p["scope"].update(allow=["169.254.169.254"])),
     ["TARGET_DENIED"]),
    ("metadata, not allowed", _set(["targets", "domains"], ["169.254.169.254"]),
     ["TARGET_DENIED"]),
    ("range overlaps metadata", lambda p: (p["targets"].update(domains=[],
                                                               ip_ranges=["169.0.0.0/8"]),
                                           p["scope"].update(allow=["169.0.0.0/8"])),
     ["TARGET_DENIED"]),
    ("rate above", _set(["scope", "rate_limit_rps"], 10.0001), ["RATE_ABOVE_CEILING"]),
    ("rate zero", _set(["scope", "rate_limit_rps"], 0), ["INVALID_REQUEST"]),
    ("rate negative", _set(["scope", "rate_limit_rps"], -1), ["INVALID_REQUEST"]),
    ("rate nan", _set(["scope", "rate_limit_rps"], math.nan), ["INVALID_REQUEST"]),
    ("rate inf", _set(["scope", "rate_limit_rps"], math.inf), ["INVALID_REQUEST"]),
    ("expired 1s", _set(["scope", "window", "not_after"], fmt(NOW - timedelta(seconds=1))),
     ["WINDOW_EXPIRED"]),
    ("expired exactly now", _set(["scope", "window", "not_after"], fmt(NOW)),
     ["WINDOW_EXPIRED"]),
    ("too long", lambda p: p["scope"]["window"].update(
        not_before=fmt(NOW), not_after=fmt(NOW + timedelta(days=90, seconds=1))),
     ["WINDOW_TOO_LONG"]),
    ("backwards window", lambda p: p["scope"]["window"].update(
        not_before=fmt(NOW + timedelta(days=2)), not_after=fmt(NOW + timedelta(days=1))),
     ["INVALID_REQUEST"]),
    ("secret in statement", _set(["authorization", "statement"], "approved, password=hunter2xx"),
     ["SECRET_INLINE"]),
    ("secret in name", _set(["name"], "aws AKIAABCDEFGHIJKLMNOP"), ["SECRET_INLINE"]),
    ("secret in approver", _set(["authorization", "approver"],
                                "-----BEGIN RSA PRIVATE KEY-----"), ["SECRET_INLINE"]),
    ("two violations", lambda p: (_set(["authorization", "confirmed"], False)(p),
                                  _set(["scope", "allow"], [])(p)),
     ["AUTH_NOT_CONFIRMED", "SCOPE_EMPTY"]),
]


@pytest.mark.parametrize("label,mutator,expected", CASES, ids=[c[0] for c in CASES])
def test_matrix(label: str, mutator: Callable[[dict[str, Any]], None], expected: list[str]) -> None:
    p = base()
    mutator(p)
    assert codes(p) == expected


def test_boundaries_that_pass() -> None:
    p = base()
    p["scope"]["rate_limit_rps"] = 10
    p["scope"]["window"].update(not_before=fmt(NOW),
                                not_after=fmt(NOW + timedelta(days=90)))
    assert codes(p) == []


def test_profile_not_enabled_wins_the_precedence() -> None:
    p = base()
    p["authorization"]["confirmed"] = False
    p["scope"]["allow"] = []
    assert codes(p, enable_lab=False) == ["PROFILE_NOT_ENABLED", "AUTH_NOT_CONFIRMED",
                                          "SCOPE_EMPTY"]


def test_standard_profile_is_unaffected_by_lab_switch() -> None:
    p = base()
    p["profile"] = "standard"
    assert codes(p, enable_lab=False) == []


def test_full_precedence_chain() -> None:
    p = base()
    p["profile"] = "lab"
    p["authorization"]["confirmed"] = False
    p["scope"]["rate_limit_rps"] = 99
    p["scope"]["window"]["not_before"] = fmt(NOW - timedelta(days=2))
    p["scope"]["window"]["not_after"] = fmt(NOW - timedelta(days=1))
    p["authorization"]["statement"] = "token=abcdefghij"
    p["scope"]["deny"] = ["target.lab.test"]
    assert codes(p, enable_lab=False) == [
        "PROFILE_NOT_ENABLED", "AUTH_NOT_CONFIRMED", "RATE_ABOVE_CEILING", "WINDOW_EXPIRED",
        "SECRET_INLINE", "TARGET_DENIED"]


def test_deny_is_reported_before_coverage() -> None:
    p = base()
    p["targets"]["domains"] = ["target.lab.test", "outside.lab.test"]
    p["scope"]["deny"] = ["target.lab.test"]
    assert codes(p) == ["TARGET_DENIED", "TARGET_NOT_IN_SCOPE"]


def test_ceiling_comes_from_settings_and_nan_ceiling_is_not_trusted() -> None:
    p = base()
    p["scope"]["rate_limit_rps"] = 3
    assert codes(p, max_rps_per_host=2.0) == ["RATE_ABOVE_CEILING"]
