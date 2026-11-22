"""Step 7: scope.deny is re-checked against every resolved IP (plan 3.1 step 7)."""

from __future__ import annotations

from policy_test_support import run_decide

from vulnscope.policy.types import RuleId

H = "cname.lab.test"


def test_public_excluded_range() -> None:
    d, _ = run_decide(H, allow=(H,), deny=("203.0.113.0/24",), table={H: ("203.0.113.5",)})
    assert d.rule_id == RuleId.EXCLUDED
    assert d.resolved_ips == ("203.0.113.5",)


def test_any_one_of_several_answers_excluded() -> None:
    d, _ = run_decide(
        H, allow=(H,), deny=("203.0.113.0/24",), table={H: ("192.0.2.1", "203.0.113.5")}
    )
    assert d.rule_id == RuleId.EXCLUDED


def test_step_7_runs_before_private_check() -> None:
    d, _ = run_decide(H, allow=(H,), deny=("10.90.0.0/24",), table={H: ("10.90.0.5",)})
    assert d.rule_id == RuleId.EXCLUDED


def test_step_6_runs_before_step_7() -> None:
    d, _ = run_decide(H, allow=(H,), deny=("169.254.0.0/16",), table={H: ("169.254.169.254",)})
    assert d.rule_id == RuleId.DENY_ALWAYS_LIST


def test_outside_exclusion_allowed() -> None:
    d, _ = run_decide(H, allow=(H,), deny=("203.0.113.0/25",), table={H: ("203.0.113.200",)})
    assert d.allowed
