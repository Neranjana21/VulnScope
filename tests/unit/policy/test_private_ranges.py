"""D8 private-range and lab rules (design 2.2)."""

from __future__ import annotations

import ipaddress as ip

import pytest
from policy_test_support import run_decide

from vulnscope.policy.private_ranges import LOOPBACK, PRIVATE_BLOCKS, parse_lab_cidr
from vulnscope.policy.types import RuleId


def test_block_lists_are_explicit() -> None:
    assert [str(n) for n in PRIVATE_BLOCKS] == [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
        "fc00::/7",
    ]
    assert [str(n) for n in LOOPBACK] == ["127.0.0.0/8", "::1/128"]


PRIVATE_SAMPLES = [
    "10.1.2.3",
    "172.16.0.1",
    "172.31.255.255",
    "192.168.1.1",
    "100.64.0.1",
    "100.127.255.255",
    "fd12::1",
]


@pytest.mark.parametrize("target", PRIVATE_SAMPLES)
def test_private_denied_without_opt_in(target: str) -> None:
    d, _ = run_decide(target, allow=("0.0.0.0/0", "::/0"))
    assert d.rule_id == RuleId.DENY_PRIVATE_RANGE


@pytest.mark.parametrize(
    ("target", "entry"),
    [
        ("10.1.2.3", "10.0.0.0/8"),
        ("10.1.2.3", "10.1.0.0/16"),
        ("10.1.2.3", "10.1.2.3"),
        ("172.16.0.1", "172.16.0.0/12"),
        ("192.168.1.1", "192.168.0.0/16"),
        ("100.64.0.1", "100.64.0.0/10"),
        ("fd12::1", "fc00::/7"),
        ("fd12::1", "fd12::/16"),
    ],
)
def test_opt_in_by_subnet_of_private_block(target: str, entry: str) -> None:
    d, _ = run_decide(target, allow=(entry,))
    assert d.allowed, d.reason


@pytest.mark.parametrize(
    ("target", "entry"),
    [
        ("10.1.2.3", "0.0.0.0/0"),
        ("10.1.2.3", "8.0.0.0/5"),
        ("fd12::1", "::/0"),
        ("10.1.2.3", "10.0.0.0/7"),
        ("172.16.0.1", "172.0.0.0/8"),
        ("100.64.0.1", "100.0.0.0/8"),
    ],
)
def test_wide_entries_do_not_opt_in(target: str, entry: str) -> None:
    d, _ = run_decide(target, allow=(entry,))
    assert d.rule_id == RuleId.DENY_PRIVATE_RANGE


def test_hostname_allow_entry_alone_does_not_opt_in() -> None:
    d, _ = run_decide("h.lab.test", allow=("h.lab.test",), table={"h.lab.test": ("10.1.2.3",)})
    assert d.rule_id == RuleId.DENY_PRIVATE_RANGE


@pytest.mark.parametrize("target", ["127.0.0.1", "127.9.9.9", "::1"])
def test_loopback_standard_always_denied_even_if_listed(target: str) -> None:
    d, _ = run_decide(target, allow=("127.0.0.0/8", "::1/128", "0.0.0.0/0", "::/0"))
    assert d.rule_id == RuleId.DENY_PRIVATE_RANGE


@pytest.mark.parametrize(
    "target", ["192.0.2.1", "198.51.100.7", "203.0.113.5", "2001:db8::1", "8.8.8.8"]
)
def test_test_net_and_public_allowed_in_standard(target: str) -> None:
    d, _ = run_decide(target, allow=("0.0.0.0/0", "::/0"))
    assert d.allowed


def test_lab_loopback_and_lab_cidr() -> None:
    kw = dict(profile="lab", lab_enabled=True, lab_cidr="10.20.0.0/16")
    for target in ("127.0.0.1", "::1", "10.20.5.5"):
        d, _ = run_decide(target, allow=("0.0.0.0/0", "::/0"), **kw)
        assert d.allowed, (target, d.reason)
    for target in ("10.21.0.1", "192.168.1.1", "192.0.2.1", "8.8.8.8", "2001:db8::1"):
        d, _ = run_decide(target, allow=("0.0.0.0/0", "::/0"), **kw)
        assert d.rule_id == RuleId.OUT_OF_SCOPE
        assert "lab" in d.reason


def test_lab_profile_not_enabled_denies() -> None:
    d, resolver = run_decide("127.0.0.1", allow=("127.0.0.1",), profile="lab")
    assert d.rule_id == RuleId.OUT_OF_SCOPE
    assert d.reason == "profile not enabled"
    assert resolver.calls == []


def test_lab_does_not_widen_scope() -> None:
    d, _ = run_decide("127.0.0.1", allow=("10.0.0.0/8",), profile="lab", lab_enabled=True)
    assert d.rule_id == RuleId.OUT_OF_SCOPE


def test_lab_never_overrides_always_deny() -> None:
    d, _ = run_decide(
        "169.254.169.254",
        allow=("0.0.0.0/0",),
        profile="lab",
        lab_enabled=True,
        lab_cidr="10.0.0.0/8",
    )
    assert d.rule_id == RuleId.DENY_ALWAYS_LIST
    d, _ = run_decide(
        "100.100.100.200",
        allow=("0.0.0.0/0",),
        profile="lab",
        lab_enabled=True,
        lab_cidr="100.64.0.0/10",
    )
    assert d.rule_id == RuleId.DENY_ALWAYS_LIST


def test_standard_profile_ignores_lab_cidr_for_opt_in() -> None:
    d, _ = run_decide("10.1.2.3", allow=("0.0.0.0/0",), lab_enabled=True, lab_cidr="10.0.0.0/8")
    assert d.rule_id == RuleId.DENY_PRIVATE_RANGE


def test_parse_lab_cidr_accepts_and_canonicalises() -> None:
    assert parse_lab_cidr(None) is None
    assert parse_lab_cidr("10.20.0.0/16") == ip.ip_network("10.20.0.0/16")
    assert parse_lab_cidr("127.0.0.0/8") == ip.ip_network("127.0.0.0/8")
    assert parse_lab_cidr("fd00:1::/48") == ip.ip_network("fd00:1::/48")
    assert parse_lab_cidr("::1/128") == ip.ip_network("::1/128")
    assert parse_lab_cidr("100.64.0.0/10") == ip.ip_network("100.64.0.0/10")
