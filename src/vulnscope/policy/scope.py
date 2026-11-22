"""Scope-entry compile and match (design sections 1 and 3).

Entries are compiled once (at ``EngagementPolicyView`` construction) into
immutable structures. Network entries are normalised to the matching domain:
IPv4-mapped IPv6 networks collapse to IPv4 (SEC-A2), so an exclusion cannot
fail open by being spelled in a form the resolved address never takes.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Sequence
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network, IPv6Network
from typing import Literal

from vulnscope.policy.target import (
    CanonicalTarget,
    IPAddress,
    IPNetwork,
    TargetParseError,
    parse_host_literal,
)

MAX_ENTRIES = 256
MAX_ENTRY_LEN = 253
_MAPPED_NET = IPv6Network("::ffff:0:0/96")

ScopeKind = Literal["allow", "deny", "expected"]


class ScopeEntryError(ValueError):
    """A scope entry is malformed. ``code`` is a stable ASCII token, never input."""

    def __init__(self, code: str) -> None:
        super().__init__(f"scope entry rejected: {code}")
        self.code = code


@dataclass(frozen=True)
class CompiledScope:
    nets: tuple[IPNetwork, ...] = ()
    exact_hosts: frozenset[str] = frozenset()
    wildcard_suffixes: tuple[str, ...] = ()


def _collapse_net(net: IPNetwork) -> IPNetwork:
    if isinstance(net, IPv6Network) and net.network_address.ipv4_mapped is not None:
        if net.prefixlen < 96:
            raise ScopeEntryError("mapped_prefix")
        v4 = int(net.network_address) & 0xFFFFFFFF
        return IPv4Network((v4, net.prefixlen - 96))
    return net


def _single_ip_net(ip: IPAddress) -> IPNetwork:
    if isinstance(ip, IPv4Address):
        return IPv4Network((int(ip), 32))
    return ipaddress.IPv6Network((int(ip), 128))


def _cidr(entry: str) -> IPNetwork:
    if not entry.isascii():
        raise ScopeEntryError("syntax")
    try:
        return _collapse_net(ipaddress.ip_network(entry, strict=True))
    except ValueError as exc:
        if isinstance(exc, ScopeEntryError):
            raise
        raise ScopeEntryError("syntax") from exc


def _network_or_none(entry: str) -> IPNetwork | None:
    """A CIDR or a single IP in any accepted spelling; None for anything else."""
    if "/" in entry:
        try:
            return _cidr(entry)
        except ScopeEntryError:
            return None
    try:
        _, ip = parse_host_literal(entry)
    except TargetParseError:
        return None
    return _single_ip_net(ip) if ip is not None else None


def _compile_one(entry: str, kind: ScopeKind) -> tuple[IPNetwork | None, str | None, str | None]:
    """Returns (network, exact_host, wildcard_suffix); exactly one is set."""
    if kind == "expected":
        net = _network_or_none(entry)
        if net is None:
            raise ScopeEntryError("expected_not_network")
        return net, None, None
    if not entry:
        raise ScopeEntryError("syntax")
    if "/" in entry:
        return _cidr(entry), None, None
    if entry.startswith("*."):
        try:
            suffix, ip = parse_host_literal(entry[2:])
        except TargetParseError as exc:
            raise ScopeEntryError("wildcard") from exc
        if ip is not None or suffix.count(".") < 1:
            raise ScopeEntryError("wildcard")
        return None, None, suffix
    try:
        host, ip = parse_host_literal(entry)
    except TargetParseError as exc:
        raise ScopeEntryError("syntax") from exc
    if ip is not None:
        return _single_ip_net(ip), None, None
    return None, host, None


def compile_scope(entries: Sequence[str], kind: ScopeKind = "allow") -> CompiledScope:
    if isinstance(entries, str | bytes) or not isinstance(entries, Sequence):
        raise TypeError("scope entries must be a sequence of str")
    if len(entries) > MAX_ENTRIES:
        raise ScopeEntryError("too_many")
    nets: dict[IPNetwork, None] = {}
    exact: set[str] = set()
    suffixes: dict[str, None] = {}
    for entry in entries:
        if not isinstance(entry, str):
            raise TypeError("scope entry must be str")
        if len(entry) > MAX_ENTRY_LEN:
            raise ScopeEntryError("too_long")
        net, host, suffix = _compile_one(entry, kind)
        if net is not None:
            nets[net] = None
        elif host is not None:
            exact.add(host)
        elif suffix is not None:
            suffixes[suffix] = None
    return CompiledScope(tuple(nets), frozenset(exact), tuple(suffixes))


def ip_matches(scope: CompiledScope, ip: IPAddress) -> bool:
    """CIDR containment (step 7); IPv4 and IPv6 never match each other."""
    return any(ip in net for net in scope.nets)


def host_matches(scope: CompiledScope, target: CanonicalTarget) -> bool:
    """String-level coverage of the canonical target (steps 3 and 4).

    A hostname is never covered by a CIDR entry; an IP literal is covered by
    network entries only. A wildcard covers any depth below its suffix, never
    the apex; an exact entry never cascades to subdomains.
    """
    if target.ip is not None:
        return ip_matches(scope, target.ip)
    host = target.host
    if host in scope.exact_hosts:
        return True
    return any(host.endswith("." + suffix) for suffix in scope.wildcard_suffixes)
