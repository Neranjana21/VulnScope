"""D9: expected_ip_ranges is checked on every resolved IP; unset does nothing."""

from __future__ import annotations

from policy_test_support import run_decide

from vulnscope.policy.types import RuleId

H = "a.lab.test"


def test_unset_means_no_check() -> None:
    d, _ = run_decide(H, allow=(H,), table={H: ("198.51.100.1",)})
    assert d.allowed


def test_inside_ranges_allowed_outside_denied() -> None:
    exp = ("203.0.113.0/24", "198.51.100.0/25")
    d, _ = run_decide(
        H, allow=(H,), table={H: ("203.0.113.5", "198.51.100.7")}, expected_ip_ranges=exp
    )
    assert d.allowed
    d, _ = run_decide(H, allow=(H,), table={H: ("198.51.100.200",)}, expected_ip_ranges=exp)
    assert d.rule_id == RuleId.RESOLVED_OUTSIDE_EXPECTED
    assert d.resolved_ips == ("198.51.100.200",)


def test_ip_literal_is_checked_too() -> None:
    d, _ = run_decide("192.0.2.5", allow=("192.0.2.0/24",), expected_ip_ranges=("203.0.113.0/24",))
    assert d.rule_id == RuleId.RESOLVED_OUTSIDE_EXPECTED


def test_expected_check_runs_after_always_deny_and_before_rate() -> None:
    d, _ = run_decide(
        H, allow=(H,), table={H: ("169.254.169.254",)}, expected_ip_ranges=("203.0.113.0/24",)
    )
    assert d.rule_id == RuleId.DENY_ALWAYS_LIST
    d, _ = run_decide(
        H,
        allow=(H,),
        table={H: ("198.51.100.1",)},
        expected_ip_ranges=("203.0.113.0/24",),
        rate_limit_rps=1.0,
    )
    assert d.rule_id == RuleId.RESOLVED_OUTSIDE_EXPECTED
