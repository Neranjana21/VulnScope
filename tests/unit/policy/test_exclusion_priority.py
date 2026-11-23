"""AC2: exclusions beat inclusions at the string level and the resolved level."""

from __future__ import annotations

from policy_test_support import run_decide

from vulnscope.policy.types import RuleId


def test_overlapping_cidrs_exclusion_wins_literal() -> None:
    allow = ("203.0.113.0/24", "203.0.113.128/25", "203.0.113.200")
    for deny in (("203.0.113.0/24",), ("203.0.113.192/26",), ("203.0.113.200/32",)):
        d, _ = run_decide("203.0.113.200", allow=allow, deny=deny)
        assert d.rule_id == RuleId.EXCLUDED


def test_union_semantics_of_overlapping_allow() -> None:
    d, _ = run_decide("203.0.113.5", allow=("203.0.113.0/25", "203.0.113.0/24"))
    assert d.allowed
    d, _ = run_decide("203.0.113.200", allow=("203.0.113.0/25",))
    assert d.rule_id == RuleId.OUT_OF_SCOPE


def test_wildcard_vs_apex_matrix() -> None:
    cases = [
        (("*.lab.test",), ("lab.test",), "lab.test", {RuleId.OUT_OF_SCOPE, RuleId.EXCLUDED}),
        (("*.lab.test",), ("lab.test",), "x.lab.test", {RuleId.ALLOW}),
        (("*.lab.test", "lab.test"), ("lab.test",), "lab.test", {RuleId.EXCLUDED}),
        (("*.lab.test", "lab.test"), ("*.lab.test",), "x.lab.test", {RuleId.EXCLUDED}),
        (("*.lab.test", "lab.test"), ("*.lab.test",), "lab.test", {RuleId.ALLOW}),
        (("*.lab.test",), ("x.lab.test",), "y.x.lab.test", {RuleId.ALLOW}),
        (("*.lab.test",), ("*.x.lab.test",), "y.x.lab.test", {RuleId.EXCLUDED}),
    ]
    for allow, deny, target, expected in cases:
        d, _ = run_decide(target, allow=allow, deny=deny, table={target: ("192.0.2.9",)})
        assert d.rule_id in expected, (allow, deny, target, d.rule_id)


def test_exclusion_at_string_level_means_no_lookup_and_resolved_level_after() -> None:
    d, r = run_decide(
        "h.lab.test",
        allow=("h.lab.test",),
        deny=("h.lab.test",),
        table={"h.lab.test": ("192.0.2.9",)},
    )
    assert d.rule_id == RuleId.EXCLUDED and r.calls == []
    d, r = run_decide(
        "h.lab.test",
        allow=("h.lab.test",),
        deny=("192.0.2.0/24",),
        table={"h.lab.test": ("192.0.2.9",)},
    )
    assert d.rule_id == RuleId.EXCLUDED and r.calls == ["h.lab.test"]


def test_ip_literal_spellings_cannot_dodge_an_exclusion() -> None:
    for target in (
        "192.0.2.9",
        "0xc0.0.2.9",
        "3221225993",
        "[::ffff:c000:209]",
        "::ffff:192.0.2.9",
    ):
        d, _ = run_decide(target, allow=("192.0.2.0/24",), deny=("192.0.2.9/32",))
        assert d.rule_id == RuleId.EXCLUDED, target
