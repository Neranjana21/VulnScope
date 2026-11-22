"""D7 plus SEC-A15 amendment: every literal, name and boundary denies in every config."""

from __future__ import annotations

import pytest
from policy_test_support import MapResolver, run_decide

from vulnscope.policy.types import RuleId

OPEN = ("0.0.0.0/0", "::/0")
CONFIGS = [
    dict(profile="standard"),
    dict(profile="lab", lab_enabled=True, lab_cidr="10.0.0.0/8"),
    dict(profile="lab", lab_enabled=True),
]


def _decide(target: str, **cfg):
    cfg = dict(cfg)
    lab_enabled = bool(cfg.pop("lab_enabled", False))
    lab_cidr = cfg.pop("lab_cidr", None)
    return run_decide(target, allow=OPEN, lab_enabled=lab_enabled, lab_cidr=lab_cidr, **cfg)


DENIED = [
    "169.254.169.254",
    "169.254.0.0",
    "169.254.255.255",
    "fe80::1",
    "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
    "fd00:ec2::254",
    "100.100.100.200",
    "168.63.129.16",
    "0.0.0.0",
    "0.255.255.255",
    "::",
    "255.255.255.255",
    "224.0.0.0",
    "239.255.255.255",
    "ff02::1",
    "ffff::1",
    "::ffff:169.254.169.254",
    "[::ffff:a9fe:a9fe]",
    "::ffff:100.100.100.200",
    "0xA9FEA9FE",
    "2852039166",
    "169.254.43518",
    "64:ff9b::a9fe:a9fe",
    "2002:a9fe:a9fe::1",
    "::a9fe:a9fe",
    # SEC-A15 amendment
    "2001::",
    "2001::5601:5601",
    "2001:0:ffff:ffff:ffff:ffff:ffff:ffff",
    "::ffff:0:a9fe:a9fe",
    "::ffff:0:0.0.0.1",
    "::ffff:0:ffff:ffff",
    "192.0.0.0",
    "192.0.0.192",
    "192.0.0.255",
    "240.0.0.0",
    "247.1.2.3",
    "255.255.255.254",
    "fec0::",
    "fec0::1",
    "feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
    "64:ff9b:1::",
    "64:ff9b:1:ffff:ffff:ffff:ffff:ffff",
]

NOT_DENIED = [
    "169.253.255.255",
    "169.255.0.0",
    "223.255.255.255",
    "2001:1::",
    "2000:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
    "::ffff:1:0:0",
    "::ffff:8.8.8.8",
    "8.8.8.8",
    "191.255.255.255",
    "192.0.1.0",
    "192.0.2.1",
    "64:ff9b:2::",
    "64:ff9b::808:808",
    "2001:db8::1",
]


@pytest.mark.parametrize("cfg", CONFIGS)
@pytest.mark.parametrize("target", DENIED)
def test_denied_and_not_resolved(target: str, cfg: dict) -> None:
    decision, resolver = _decide(target, **cfg)
    assert not decision.allowed
    assert decision.rule_id == RuleId.DENY_ALWAYS_LIST
    assert resolver.calls == []
    assert decision.resolved_ips != ()


@pytest.mark.parametrize("target", NOT_DENIED)
def test_adjacent_addresses_not_denied_by_list(target: str) -> None:
    decision, _ = _decide(target)
    assert decision.rule_id != RuleId.DENY_ALWAYS_LIST, target
    assert decision.allowed, (target, decision.reason)


def test_mapped_public_collapses_to_ipv4_and_is_allowed() -> None:
    decision, _ = _decide("::ffff:8.8.8.8")
    assert decision.allowed
    assert decision.resolved_ips == ("8.8.8.8",)


def test_fc00_still_private_and_opt_in_works() -> None:
    d, _ = _decide("fc00::1")
    assert d.rule_id == RuleId.DENY_PRIVATE_RANGE
    d, _ = run_decide("fc00::1", allow=("fc00::/7",))
    assert d.allowed


def test_metadata_ip_cannot_be_exposed_by_private_opt_in() -> None:
    d, _ = run_decide("100.100.100.200", allow=("100.64.0.0/10",))
    assert d.rule_id == RuleId.DENY_ALWAYS_LIST
    d, _ = run_decide("fd00:ec2::254", allow=("fc00::/7",))
    assert d.rule_id == RuleId.DENY_ALWAYS_LIST
    d, _ = run_decide("100.100.100.201", allow=("100.64.0.0/10",))
    assert d.allowed


@pytest.mark.parametrize(
    "name",
    [
        "metadata",
        "METADATA.",
        "metadata.google.internal.",
        "x.metadata.google.internal",
        "instance-data",
        "INSTANCE-DATA.",
        "instance-data.ec2.internal",
        "x.instance-data.ec2.internal",
    ],
)
@pytest.mark.parametrize("with_allow", [True, False])
def test_denied_names_with_and_without_allow(name: str, with_allow: bool) -> None:
    resolver = MapResolver({})
    allow = (
        (
            "*.google.internal",
            "metadata",
            "instance-data",
            "*.ec2.internal",
            "metadata.google.internal",
            "instance-data.ec2.internal",
        )
        if with_allow
        else ()
    )
    decision, _ = run_decide(name, allow=allow, resolver=resolver)
    assert decision.rule_id == RuleId.DENY_ALWAYS_LIST
    assert resolver.calls == []


@pytest.mark.parametrize(
    "name",
    [
        "my-instance-data",
        "instance-data.lab.test",
        "metadata.lab.test",
        "xmetadata.google.internal.test",
    ],
)
def test_lookalike_names_not_denied_by_list(name: str) -> None:
    decision, _ = run_decide(name, allow=(name,), table={name: ("192.0.2.1",)})
    assert decision.allowed
