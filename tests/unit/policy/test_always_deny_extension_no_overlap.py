"""MECHANICAL GUARD (design 11.3): no always-deny network may overlap protected ranges."""

from __future__ import annotations

import ipaddress as ip

from vulnscope.policy.denylist import (
    ALWAYS_DENY_NETWORKS,
    D7_AMENDMENT_1_NETWORKS,
    D7_EMBEDDED_NETWORKS,
    D7_LITERAL_NETWORKS,
)
from vulnscope.policy.private_ranges import LOOPBACK, PRIVATE_BLOCKS

DOC_RANGES = tuple(
    ip.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)
PROTECTED = (*LOOPBACK, *PRIVATE_BLOCKS, *DOC_RANGES)


def test_amendment_overlaps_nothing_protected() -> None:
    for net in (*D7_AMENDMENT_1_NETWORKS, *D7_EMBEDDED_NETWORKS):
        for other in PROTECTED:
            assert not net.overlaps(other), (str(net), str(other))  # type: ignore[arg-type]


def test_amendment_vs_strictest_lab_cidrs() -> None:
    strict = [*LOOPBACK, *PRIVATE_BLOCKS]
    for net in (*D7_AMENDMENT_1_NETWORKS, *D7_EMBEDDED_NETWORKS):
        for lab in strict:
            assert not net.overlaps(lab)  # type: ignore[arg-type]


def test_literal_overlaps_private_only_at_the_two_carve_outs() -> None:
    allowed = {ip.ip_network("100.100.100.200/32"), ip.ip_network("fd00:ec2::254/128")}
    seen = set()
    for net in D7_LITERAL_NETWORKS:
        for other in PROTECTED:
            if net.overlaps(other):  # type: ignore[arg-type]
                seen.add(net)
                assert net in allowed, (str(net), str(other))
    assert seen == allowed


def test_all_networks_is_the_three_named_tuples() -> None:
    assert (
        ALWAYS_DENY_NETWORKS == D7_LITERAL_NETWORKS + D7_AMENDMENT_1_NETWORKS + D7_EMBEDDED_NETWORKS
    )


LAB_FORMS = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "::1/128",
    "fc00::/48",
    "fd00::/48",
    "fd00:ec2::/48",
    "fd12:3456:789a::/48",
]


def test_whole_always_deny_list_overlaps_nothing_protected_except_carve_outs() -> None:
    carve = {ip.ip_network("100.100.100.200/32"), ip.ip_network("fd00:ec2::254/128")}
    for net in ALWAYS_DENY_NETWORKS:
        for other in (*PROTECTED, *(ip.ip_network(t) for t in LAB_FORMS)):
            if net.version == other.version and net.overlaps(other):
                assert net in carve, (str(net), str(other))


def test_ipv6_loopback_is_never_always_deny_but_unspecified_is() -> None:
    assert not any(ip.ip_address("::1") in n for n in ALWAYS_DENY_NETWORKS)
    assert any(ip.ip_address("::") in n for n in ALWAYS_DENY_NETWORKS)


def test_embedded_ranges_fully_covered_except_loopback() -> None:
    for rng in ("64:ff9b::/96", "2002::/16", "::/96"):
        base = ip.ip_network(rng)
        pieces = [n for n in ALWAYS_DENY_NETWORKS if n.version == 6 and n.subnet_of(base)]
        covered = sum(n.num_addresses for n in ip.collapse_addresses(pieces))
        assert covered == base.num_addresses - (1 if ip.ip_address("::1") in base else 0)
