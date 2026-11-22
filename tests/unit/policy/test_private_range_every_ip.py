"""SEC-A1: the private and lab rules run on EVERY resolved IP, order independent."""

from __future__ import annotations

import itertools

from hypothesis import given, settings
from hypothesis import strategies as st
from policy_test_support import run_decide

from vulnscope.policy.types import RuleId

H = "multi.lab.test"
PUBLIC = "192.0.2.1"
PRIV = "10.0.0.5"


def _run(ips: tuple[str, ...], **kw):
    allow = kw.pop("allow", (H,))
    return run_decide(H, allow=allow, table={H: ips}, **kw)[0]


def test_public_and_rfc1918_deny_in_both_orders_standard() -> None:
    for ips in ((PUBLIC, PRIV), (PRIV, PUBLIC)):
        d = _run(ips)
        assert d.rule_id == RuleId.DENY_PRIVATE_RANGE
        assert d.resolved_ips == ips


def test_opt_in_covering_only_one_still_denies() -> None:
    for ips in ((PUBLIC, PRIV), (PRIV, PUBLIC)):
        d = _run(ips, allow=(H, "10.0.0.0/8"))
        assert d.allowed, "opt-in covers the private member; public needs none"
    for ips in (("10.0.0.5", "10.1.0.5"), ("10.1.0.5", "10.0.0.5")):
        d = _run(ips, allow=(H, "10.0.0.0/16"))
        assert d.rule_id == RuleId.DENY_PRIVATE_RANGE


def test_lab_every_ip_must_be_loopback_or_lab_cidr() -> None:
    kw = dict(profile="lab", lab_enabled=True, lab_cidr="10.20.0.0/16")
    for ips in (("127.0.0.1", PUBLIC), (PUBLIC, "127.0.0.1"), ("10.20.0.1", "10.21.0.1")):
        d = _run(ips, **kw)
        assert d.rule_id == RuleId.OUT_OF_SCOPE
    d = _run(("127.0.0.1", "10.20.0.9"), **kw)
    assert d.allowed


def test_allow_100_64_cannot_expose_metadata_among_answers() -> None:
    for ips in (("100.64.0.1", "100.100.100.200"), ("100.100.100.200", "100.64.0.1")):
        d = _run(ips, allow=(H, "100.64.0.0/10"))
        assert d.rule_id == RuleId.DENY_ALWAYS_LIST


def test_allow_fc00_cannot_expose_aws_v6_metadata() -> None:
    d = _run(("fd12::1", "fd00:ec2::254"), allow=(H, "fc00::/7"))
    assert d.rule_id == RuleId.DENY_ALWAYS_LIST


def test_allow_decision_resolved_ips_is_the_full_passing_set() -> None:
    d = _run((PUBLIC, "198.51.100.1", PUBLIC))
    assert d.allowed
    assert d.resolved_ips == (PUBLIC, "198.51.100.1")  # canonical, de-duplicated, order kept


@given(st.permutations([PUBLIC, PRIV, "198.51.100.9", "172.16.0.9"]))
@settings(max_examples=60, deadline=None)
def test_verdict_is_order_independent(order: list[str]) -> None:
    d = _run(tuple(order))
    assert d.rule_id == RuleId.DENY_PRIVATE_RANGE
    d = _run(tuple(order), allow=(H, "10.0.0.0/8", "172.16.0.0/12"))
    assert d.allowed
    assert set(d.resolved_ips) == set(order)


def test_all_permutations_agree_on_allow_flag() -> None:
    sets = (PUBLIC, PRIV, "100.64.0.9")
    flags = {_run(p).allowed for p in itertools.permutations(sets)}
    assert flags == {False}
