"""D8 private-range and lab rules (design 2.2). Pure, explicit block lists.

``ipaddress.is_private`` is deliberately NOT used: it is True for TEST-NET
documentation ranges, which must stay allowed in the ``standard`` profile.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Sequence
from typing import Literal

from vulnscope.policy.target import IPAddress, IPNetwork
from vulnscope.policy.types import RuleId

PRIVATE_BLOCKS: tuple[IPNetwork, ...] = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("fc00::/7"),
)
LOOPBACK: tuple[IPNetwork, ...] = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
)
_MIN_PREFIX_V4 = 8
_MIN_PREFIX_V6 = 48


def subnet_of(inner: IPNetwork, outer: IPNetwork) -> bool:
    """Version-safe ``inner.subnet_of(outer)``."""
    if inner.version != outer.version:
        return False
    return inner.network_address in outer and inner.broadcast_address in outer


def in_any(ip: IPAddress, nets: Sequence[IPNetwork]) -> bool:
    return any(ip in net for net in nets)


def is_private_opt_in_net(net: IPNetwork) -> bool:
    """An allow network that may opt a private address in: a subnet of ONE private block."""
    return any(subnet_of(net, block) for block in PRIVATE_BLOCKS)


def parse_lab_cidr(text: str | None) -> IPNetwork | None:
    """Validate ``VULNSCOPE_LAB_CIDR``. None -> None; anything unsafe raises ValueError.

    The network must lie inside ONE private block or loopback and be no shorter
    than /8 (IPv4) or /48 (IPv6), so a mistaken value can never admit the
    internet or a link-local range.
    """
    if text is None:
        return None
    if not isinstance(text, str):
        raise TypeError("lab_cidr must be str or None")
    if not text.isascii():
        raise ValueError("invalid lab CIDR")
    net = ipaddress.ip_network(text, strict=True)  # ValueError on garbage / empty
    floor = _MIN_PREFIX_V4 if net.version == 4 else _MIN_PREFIX_V6
    if net.prefixlen < floor:
        raise ValueError("lab CIDR too broad")
    if not any(subnet_of(net, block) for block in (*PRIVATE_BLOCKS, *LOOPBACK)):
        raise ValueError("lab CIDR outside private and loopback ranges")
    return net


def private_verdict(
    ip: IPAddress,
    *,
    profile: Literal["standard", "lab"],
    lab_net: IPNetwork | None,
    allow_nets: Sequence[IPNetwork],
) -> tuple[RuleId, str] | None:
    """Step 8 for ONE resolved IP: None passes; otherwise (rule, reason).

    ``lab_net`` is only consulted under the ``lab`` profile; ``standard``
    ignores the lab CIDR everywhere, including as a private opt-in.
    """
    if profile == "lab":
        if in_any(ip, LOOPBACK) or (lab_net is not None and ip in lab_net):
            return None
        return RuleId.OUT_OF_SCOPE, "lab profile permits only loopback and the lab CIDR"
    if in_any(ip, LOOPBACK):
        return RuleId.DENY_PRIVATE_RANGE, "loopback is permitted only under the lab profile"
    if in_any(ip, PRIVATE_BLOCKS):
        for net in allow_nets:
            if ip in net and is_private_opt_in_net(net):
                return None
        return RuleId.DENY_PRIVATE_RANGE, "private range requires an explicit CIDR in scope.allow"
    return None
