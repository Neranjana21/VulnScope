"""Stress (R1): SEC-A15 mechanical guard, written independently of the implementer's own overlap test.
Source of truth: task-a-design.md 11.3 plus the owner decisions of 2026-11-19 and 2026-11-23.

Hard constraint: nothing in ``ALWAYS_DENY_NETWORKS`` may overlap the five private blocks an explicit
CIDR must be able to allow, loopback (127.0.0.0/8 and ::1/128), any lab CIDR ``parse_lab_cidr``
accepts, RFC 5737 / RFC 3849 documentation space, or any address literal used by the R1 stress
tests and fixtures (scanned from the files themselves, so a new literal cannot slip in).

EXPLICIT EXCEPTIONS (stated, not silent):
* private-block overlap: only the single-address D7 carve-outs 100.100.100.200/32 (inside
  100.64.0.0/10) and fd00:ec2::254/128 (inside fc00::/7);
* R1 literals: 169.254.169.254 (expected to be denied, D7) and the scope-entry network 169.0.0.0/8
  (an allow entry that contains 169.254.0.0/16 by design);
* the owner-approved embedded-IPv4 ranges (64:ff9b::/96, 2002::/16, ::/96) may be represented as
  split sub-networks that leave ::1 out; they are NOT allowed to contain ::1 as a whole.
Not in the list (owner decision): 198.18.0.0/15 and ISATAP.
"""
# ruff: noqa: E501
from __future__ import annotations

import ipaddress as ip
import re
from pathlib import Path

import pytest

from vulnscope.policy.denylist import ALWAYS_DENY_NETWORKS
from vulnscope.policy.private_ranges import parse_lab_cidr

PRIVATE = [ip.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")]
LOOPBACK = [ip.ip_network("127.0.0.0/8"), ip.ip_network("::1/128")]
DOCS = [ip.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]
CARVE_OUTS = {ip.ip_network("100.100.100.200/32"), ip.ip_network("fd00:ec2::254/128")}

D7_LITERALS = {ip.ip_network(n) for n in (
    "169.254.0.0/16", "fe80::/10", "fd00:ec2::254/128", "100.100.100.200/32", "168.63.129.16/32",
    "0.0.0.0/8", "::/128", "255.255.255.255/32", "224.0.0.0/4", "ff00::/8")}
APPROVED = {ip.ip_network(n) for n in (
    "2001::/32", "::ffff:0:0:0/96", "192.0.0.0/24", "240.0.0.0/4", "64:ff9b:1::/48", "fec0::/10")}
EMBEDDED_RANGES = [ip.ip_network(n) for n in ("64:ff9b::/96", "2002::/16", "::/96")]

TESTS_ROOT = Path(__file__).resolve().parents[2]
SELF_FILES = {Path(__file__).name, "test_embedded_ipv4_always_deny.py"}


def _overlaps(a, b) -> bool:
    return a.version == b.version and a.overlaps(b)


def _bad(deny_nets, others):
    return [(str(d), str(o)) for d in deny_nets for o in others if _overlaps(d, o)]


def test_list_is_non_empty_tuple_of_networks() -> None:
    assert len(ALWAYS_DENY_NETWORKS) >= len(D7_LITERALS) + len(APPROVED)
    assert all(isinstance(n, ip.IPv4Network | ip.IPv6Network) for n in ALWAYS_DENY_NETWORKS)


def test_d7_literals_and_the_six_approved_ranges_are_present_exactly() -> None:
    present = set(ALWAYS_DENY_NETWORKS)
    assert D7_LITERALS <= present, f"missing D7: {sorted(map(str, D7_LITERALS - present))}"
    assert APPROVED <= present, f"missing SEC-A15: {sorted(map(str, APPROVED - present))}"


def test_no_unexpected_extra_ranges() -> None:
    """Anything beyond D7 + the six approved must be a piece of one of the three embedded ranges."""
    extras = [n for n in ALWAYS_DENY_NETWORKS if n not in D7_LITERALS and n not in APPROVED]
    stray = [str(n) for n in extras if not any(n.version == r.version and n.subnet_of(r) for r in EMBEDDED_RANGES)]
    assert not stray, f"always-deny entries outside the approved set: {stray}"


@pytest.mark.parametrize("rng", EMBEDDED_RANGES, ids=str)
def test_embedded_ipv4_ranges_are_fully_covered_except_loopback(rng) -> None:
    """Owner decision 2026-11-23: 64:ff9b::/96, 2002::/16 and ::/96 are always-deny, ::1 carved out.
    Representation is free (one entry, or split pieces that skip ::1); coverage is exact."""
    pieces = [n for n in ALWAYS_DENY_NETWORKS if n.version == 6 and n.subnet_of(rng)]
    covered = sum(n.num_addresses for n in ip.collapse_addresses(pieces))
    expected = rng.num_addresses - (1 if ip.ip_address("::1") in rng else 0)
    assert covered == expected, f"{rng}: {covered} of {expected} addresses covered"
    assert not any(ip.ip_address("::1") in n for n in ALWAYS_DENY_NETWORKS)


def test_198_18_and_isatap_are_not_always_deny() -> None:
    for text in ("198.18.0.0", "198.18.0.1", "198.19.255.255", "::5efe:192.0.2.1", "2001:db8::5efe:192.0.2.1"):
        addr = ip.ip_address(text)
        assert not any(addr.version == n.version and addr in n for n in ALWAYS_DENY_NETWORKS), text
    assert ip.ip_network("198.18.0.0/15") not in ALWAYS_DENY_NETWORKS


def test_no_overlap_with_private_blocks_except_the_two_stated_carve_outs() -> None:
    hits = [(d, o) for d, o in _bad(ALWAYS_DENY_NETWORKS, PRIVATE) if ip.ip_network(d) not in CARVE_OUTS]
    assert not hits, f"always-deny overlaps a private block: {hits}"
    assert all(any(c.version == n.version and c.subnet_of(n) for n in PRIVATE) for c in CARVE_OUTS), (
        "carve-outs must really sit inside a private block"
    )


def test_no_overlap_with_loopback_including_ipv6_loopback() -> None:
    assert not _bad(ALWAYS_DENY_NETWORKS, LOOPBACK), "::1 is loopback: governed by the profile, never always-deny"
    assert not any(ip.ip_address("::1") in n for n in ALWAYS_DENY_NETWORKS)
    assert not any(ip.ip_address("127.0.0.1") in n for n in ALWAYS_DENY_NETWORKS)


def test_no_overlap_with_documentation_ranges() -> None:
    assert not _bad(ALWAYS_DENY_NETWORKS, DOCS)


# parse_lab_cidr floors: no shorter than /8 (v4) and /48 (v6), so fc00::/7 itself is not a lab CIDR;
# the widest accepted IPv6 forms are the /48s below. The two stated carve-outs may sit inside a lab
# CIDR (100.64.0.0/10, fd00:ec2::/48) by design: they are D7 single addresses.
LAB_ACCEPTED = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/48", "fd00::/48", "fd00:ec2::/48", "127.0.0.0/8", "::1/128", "127.0.0.1/32", "10.1.2.0/24", "fd12:3456:789a::/48"]


@pytest.mark.parametrize("text", LAB_ACCEPTED)
def test_no_overlap_with_any_lab_cidr_parse_lab_cidr_accepts(text: str) -> None:
    net = parse_lab_cidr(text)
    assert net is not None and net == ip.ip_network(text), "fixture: parse_lab_cidr must accept this lab CIDR"
    hits = [(d, o) for d, o in _bad(ALWAYS_DENY_NETWORKS, [net]) if ip.ip_network(d) not in CARVE_OUTS]
    assert not hits, text


def test_lab_cidrs_that_overlap_always_deny_are_rejected_by_parse_lab_cidr() -> None:
    for text in ("169.254.0.0/16", "0.0.0.0/0", "::/0", "64:ff9b::/96", "2002::/16", "240.0.0.0/4"):
        with pytest.raises(ValueError):
            parse_lab_cidr(text)


# ---- address literals used by R1 stress tests and fixtures, scanned from the files
# Not preceded by a word char, dot or colon (so IPv6 tails and "0x1_0.0.0.1" are not read as IPv4).
V4 = re.compile(r"(?<![0-9A-Za-z_.:])([0-9]{1,3}(?:\.[0-9]{1,3}){3})(?:/([0-9]{1,2}))?(?![0-9.:])")
R1_EXCEPT_ADDR = {ip.ip_address("169.254.169.254")}
R1_EXCEPT_NET = {ip.ip_network("169.0.0.0/8")}


def _scan() -> tuple[set, set]:
    addrs, nets = set(), set()
    for base in (TESTS_ROOT / "stress", TESTS_ROOT / "fixtures"):
        for path in sorted(base.rglob("*")):
            # the boundary file lists always-deny literals ON PURPOSE (expected DENY rows)
            if path.suffix not in {".py", ".json", ".txt"} or path.name in SELF_FILES:
                continue
            for m in V4.finditer(path.read_text(encoding="utf-8", errors="replace")):
                try:
                    if m.group(2) is None:
                        addrs.add(ip.ip_address(m.group(1)))
                    elif int(m.group(2)) >= 8:  # /0../7 are "allow everything" entries, not literals
                        nets.add(ip.ip_network(f"{m.group(1)}/{m.group(2)}", strict=False))
                except ValueError:
                    continue  # 256.1.1.1, 08.1.1.1 ... are deliberately invalid inputs
    return addrs, nets


def test_r1_literal_scan_is_not_vacuous() -> None:
    addrs, nets = _scan()
    assert ip.ip_address("192.0.2.1") in addrs and ip.ip_address("127.0.0.1") in addrs
    assert ip.ip_network("10.0.0.0/8") in nets and len(addrs) >= 8


def test_no_always_deny_range_contains_an_r1_address_literal_or_overlaps_an_r1_network() -> None:
    addrs, nets = _scan()
    v4_deny = [n for n in ALWAYS_DENY_NETWORKS if n.version == 4]
    bad_addrs = sorted(str(a) for a in addrs - R1_EXCEPT_ADDR if any(a in n for n in v4_deny))
    bad_nets = sorted(str(n) for n in nets - R1_EXCEPT_NET if any(n.overlaps(d) for d in v4_deny))
    assert not bad_addrs, f"R1 address literals inside an always-deny range: {bad_addrs}"
    assert not bad_nets, f"R1 networks overlapping an always-deny range: {bad_nets}"
    assert all(any(a in n for n in v4_deny) for a in R1_EXCEPT_ADDR), "stated exception must really be D7"


def test_r1_ipv6_literals_are_clear_of_always_deny() -> None:
    for text in ("2001:db8::1", "2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"):
        assert not any(ip.ip_address(text) in n for n in ALWAYS_DENY_NETWORKS if n.version == 6), text
