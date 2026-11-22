"""MECHANICAL GUARD (design 11.3): no always-deny network may overlap protected ranges."""

from __future__ import annotations

import ipaddress as ip

from vulnscope.policy.denylist import (
    ALWAYS_DENY_NETWORKS,
    D7_AMENDMENT_1_NETWORKS,
    D7_LITERAL_NETWORKS,
)
from vulnscope.policy.private_ranges import LOOPBACK, PRIVATE_BLOCKS

DOC_RANGES = tuple(
    ip.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)
PROTECTED = (*LOOPBACK, *PRIVATE_BLOCKS, *DOC_RANGES)


def test_amendment_overlaps_nothing_protected() -> None:
    for net in D7_AMENDMENT_1_NETWORKS:
        for other in PROTECTED:
            assert not net.overlaps(other), (str(net), str(other))  # type: ignore[arg-type]


def test_amendment_vs_strictest_lab_cidrs() -> None:
    strict = [*LOOPBACK, *PRIVATE_BLOCKS]
    for net in D7_AMENDMENT_1_NETWORKS:
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


def test_all_networks_is_the_two_named_tuples() -> None:
    assert ALWAYS_DENY_NETWORKS == D7_LITERAL_NETWORKS + D7_AMENDMENT_1_NETWORKS
