"""Always-deny list (decisions D7 plus the 2026-11-19 SEC-A15 amendment).

``scope.allow`` and the profile can never exempt anything listed here. The two
named tuples keep the amendment auditable. Names are matched on the canonical
host BEFORE any resolution; addresses are matched on every resolved IP.

Hard constraint, enforced by ``test_always_deny_extension_no_overlap.py``: no
amendment network may overlap loopback, the D8 private ranges, any lab CIDR or
a documentation range. The only permitted overlaps with private ranges are the
two intentional single-address carve-outs in the literal list.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json

from vulnscope.policy.target import IPAddress, IPNetwork, embedded_ipv4_candidates

RULESET_SEMVER = "1.0.0"

D7_LITERAL_NETWORKS: tuple[IPNetwork, ...] = (
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fd00:ec2::254/128"),
    ipaddress.ip_network("100.100.100.200/32"),
    ipaddress.ip_network("168.63.129.16/32"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("255.255.255.255/32"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("ff00::/8"),
)

D7_AMENDMENT_1_NETWORKS: tuple[IPNetwork, ...] = (
    ipaddress.ip_network("2001::/32"),  # Teredo
    ipaddress.ip_network("::ffff:0:0:0/96"),  # SIIT / IPv4-translated (not IPv4-mapped)
    ipaddress.ip_network("64:ff9b:1::/48"),  # local-use NAT64
    ipaddress.ip_network("192.0.0.0/24"),  # IETF protocol assignments (legacy OCI metadata)
    ipaddress.ip_network("240.0.0.0/4"),  # reserved, class E
    ipaddress.ip_network("fec0::/10"),  # deprecated site-local
)

# Owner decision 2026-11-23: IPv4-embedding IPv6 ranges are denied WHOLE, whatever IPv4 they carry.
# IPv4-compatible ::/96 is split so that ``::1`` (loopback, governed by the lab profile) is skipped;
# ``::`` is already a D7 literal, so the split also skips ``::/127`` (``::`` and ``::1``).
D7_EMBEDDED_NETWORKS: tuple[IPNetwork, ...] = (
    ipaddress.ip_network("64:ff9b::/96"),  # NAT64
    ipaddress.ip_network("2002::/16"),  # 6to4
    *sorted(ipaddress.IPv6Network("::/96").address_exclude(ipaddress.IPv6Network("::/127"))),
)

ALWAYS_DENY_NETWORKS: tuple[IPNetwork, ...] = (
    D7_LITERAL_NETWORKS + D7_AMENDMENT_1_NETWORKS + D7_EMBEDDED_NETWORKS
)
ALWAYS_DENY_EXACT_NAMES: frozenset[str] = frozenset({"metadata", "instance-data"})
# The name itself and any subdomain of it.
ALWAYS_DENY_NAME_SUFFIXES: tuple[str, ...] = (
    "metadata.google.internal",
    "instance-data.ec2.internal",
)


def match_always_deny_ip(ip: IPAddress) -> str | None:
    """Which always-deny network contains ``ip`` (for the reason text), else None."""
    for net in ALWAYS_DENY_NETWORKS:
        if ip in net:
            return str(net)
    return None


def match_always_deny_ip_or_embedded(ip: IPAddress) -> str | None:
    """As :func:`match_always_deny_ip`, also over IPv4 addresses embedded in ``ip``."""
    hit = match_always_deny_ip(ip)
    if hit is not None:
        return hit
    for candidate in embedded_ipv4_candidates(ip):
        hit = match_always_deny_ip(candidate)
        if hit is not None:
            return hit
    return None


def match_always_deny_host(host: str) -> str | None:
    """Name-level check on a CANONICAL host (lowercase, no trailing dot)."""
    if host in ALWAYS_DENY_EXACT_NAMES:
        return host
    for suffix in ALWAYS_DENY_NAME_SUFFIXES:
        if host == suffix or host.endswith("." + suffix):
            return suffix
    return None


def network_overlaps_always_deny(net: IPNetwork) -> bool:
    """Overlap (not containment) test used for target RANGES (engagement_check)."""
    return any(net.version == deny.version and net.overlaps(deny) for deny in ALWAYS_DENY_NETWORKS)


def compute_policy_version(*, lab_enabled: bool, lab_cidr: str | None) -> str:
    """``<semver>+<sha256 prefix>`` over the ruleset and the raw lab inputs.

    ``lab_cidr`` is hashed as the raw string and never parsed (RC8); it only
    counts while the lab is enabled, because a disabled lab ignores it.
    """
    if lab_cidr is not None and not isinstance(lab_cidr, str):
        raise TypeError("lab_cidr must be str or None")
    material = {
        "semver": RULESET_SEMVER,
        "deny_networks": sorted(str(n) for n in ALWAYS_DENY_NETWORKS),
        "deny_exact": sorted(ALWAYS_DENY_EXACT_NAMES),
        "deny_suffixes": sorted(ALWAYS_DENY_NAME_SUFFIXES),
        "lab_enabled": bool(lab_enabled),
        "lab_cidr": lab_cidr if lab_enabled else None,
    }
    blob = json.dumps(material, sort_keys=True, separators=(",", ":"))
    return f"{RULESET_SEMVER}+{hashlib.sha256(blob.encode('utf-8')).hexdigest()[:16]}"
