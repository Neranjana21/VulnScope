"""embedded_ipv4_candidates / embedded_ipv4_networks (design 2.2, 11.4)."""

from __future__ import annotations

import ipaddress as ip

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from vulnscope.policy.target import embedded_ipv4_candidates, embedded_ipv4_networks


def A(text: str) -> ip.IPv4Address | ip.IPv6Address:
    return ip.ip_address(text)


@pytest.mark.parametrize(
    ("addr", "expected"),
    [
        ("64:ff9b::a9fe:a9fe", "169.254.169.254"),
        ("64:ff9b::808:808", "8.8.8.8"),
        ("2002:a9fe:a9fe::1", "169.254.169.254"),
        ("2002:a9fe:a9fe:ffff:ffff:ffff:ffff:ffff", "169.254.169.254"),
        ("::a9fe:a9fe", "169.254.169.254"),
        ("::0.0.0.2", "0.0.0.2"),
    ],
)
def test_embedded_forms(addr: str, expected: str) -> None:
    assert embedded_ipv4_candidates(A(addr)) == (ip.IPv4Address(expected),)


@pytest.mark.parametrize(
    "addr", ["::", "::1", "2001:db8::1", "fd00::1", "192.0.2.1", "64:ff9b:1::1"]
)
def test_no_embedding(addr: str) -> None:
    assert embedded_ipv4_candidates(A(addr)) == ()


def test_networks_projection_basic() -> None:
    assert embedded_ipv4_networks(ip.ip_network("64:ff9b::/96")) == (ip.ip_network("0.0.0.0/0"),)
    assert embedded_ipv4_networks(ip.ip_network("::/0")) == (ip.ip_network("0.0.0.0/0"),)
    assert embedded_ipv4_networks(ip.ip_network("2002:a9fe::/32")) == (
        ip.ip_network("169.254.0.0/16"),
    )
    assert embedded_ipv4_networks(ip.ip_network("64:ff9b::a9fe:0/112")) == (
        ip.ip_network("169.254.0.0/16"),
    )
    assert embedded_ipv4_networks(ip.ip_network("2001:db8::/32")) == ()
    assert embedded_ipv4_networks(ip.ip_network("10.0.0.0/8")) == ()


@given(st.integers(min_value=0, max_value=2**128 - 1), st.integers(min_value=0, max_value=128))
@settings(max_examples=300, deadline=None)
def test_projection_is_sound(value: int, prefix: int) -> None:
    """Every embedded candidate of an address in the net lies in a projected net."""
    net = ip.IPv6Network((value >> (128 - prefix) << (128 - prefix), prefix))
    nets = embedded_ipv4_networks(net)
    for host in (net.network_address, net.broadcast_address):
        for cand in embedded_ipv4_candidates(host):
            assert any(cand in n for n in nets)
