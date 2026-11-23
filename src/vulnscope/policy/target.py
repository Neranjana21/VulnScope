"""Single canonical target parser (design section 3, fail closed).

Every comparison in ``policy/`` is made between canonical forms produced here:
targets, scope entries and resolver output all pass through these functions.
Pure stdlib, no I/O. Any ambiguity raises :class:`TargetParseError`, whose
``code`` is a stable ASCII token that never echoes the raw input.

Numeric safety (SEC-A4): every numeric test uses explicit ASCII regexes. The
lenient ``str`` predicates and ``int()`` on unvalidated text are never used.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from typing import Literal

MAX_TARGET_LEN = 2048
MAX_HOST_LEN = 253

_PORT_RE = re.compile(r"[0-9]{1,5}", re.ASCII)
_LABEL_RE = re.compile(r"[a-z0-9_-]{1,63}", re.ASCII)
_DEC_RE = re.compile(r"[0-9]+", re.ASCII)
_HEX_RE = re.compile(r"0[xX][0-9a-fA-F]*", re.ASCII)
_OCT_RE = re.compile(r"0[0-9]+", re.ASCII)
_NUMERIC_LAST_RE = re.compile(r"[0-9]+|0[xX][0-9a-fA-F]*", re.ASCII)
_CIDR_PATH_RE = re.compile(r"/[0-9]{1,3}", re.ASCII)
_AUTHORITY_END_RE = re.compile(r"[/?#]")

_DEVIATIONS = frozenset("ßς‌‍")
_META_AFTER_NFKC = frozenset("@\\%#?/: ")
_BAD_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zs", "Zl", "Zp"})

_NAT64 = IPv6Network("64:ff9b::/96")
_SIXTO4 = IPv6Network("2002::/16")
_COMPAT = IPv6Network("::/96")
_MAPPED = IPv6Network("::ffff:0:0/96")
_ALL_V4 = IPv4Network("0.0.0.0/0")

IPAddress = IPv4Address | IPv6Address
IPNetwork = IPv4Network | IPv6Network


class TargetParseError(ValueError):
    """Hostile or ambiguous target text. ``code`` is a stable ASCII token."""

    def __init__(self, code: str) -> None:
        super().__init__(f"unparseable target: {code}")
        self.code = code


@dataclass(frozen=True)
class CanonicalTarget:
    host: str
    ip: IPAddress | None
    port: int | None
    scheme: Literal["http", "https"] | None


def _reject_chars(text: str) -> None:
    for ch in text:
        if ch in "\\%" or ch.isspace() or unicodedata.category(ch) in _BAD_CATEGORIES:
            raise TargetParseError("charset")


def _collapse_mapped(ip: IPAddress) -> IPAddress:
    if isinstance(ip, IPv6Address):
        mapped = ip.ipv4_mapped
        if mapped is not None:
            return mapped
    return ip


def _parse_ipv4_numeric(labels: list[str]) -> IPv4Address:
    """glibc ``inet_aton`` forms (WHATWG 'ends in a number'): 1-4 parts."""
    if len(labels) > 4:
        raise TargetParseError("ipv4")
    values: list[int] = []
    for part in labels:
        if len(part) > 20:
            raise TargetParseError("ipv4")
        if _HEX_RE.fullmatch(part):
            digits = part[2:]
            values.append(int(digits, 16) if digits else 0)
        elif _OCT_RE.fullmatch(part):
            if "8" in part or "9" in part:
                raise TargetParseError("ipv4")
            values.append(int(part, 8))
        elif _DEC_RE.fullmatch(part):
            values.append(int(part, 10))
        else:
            raise TargetParseError("ipv4")
    *head, last = values
    if any(v > 255 for v in head):
        raise TargetParseError("ipv4")
    if last >= 256 ** (5 - len(values)):
        raise TargetParseError("ipv4")
    total = last
    for i, v in enumerate(head):
        total += v << (8 * (3 - i))
    return IPv4Address(total)


def _check_punycode(label: str) -> None:
    try:
        decoded = label.encode("ascii").decode("idna")
        again = decoded.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise TargetParseError("punycode") from exc
    if again != label:
        raise TargetParseError("punycode")


def _canonical_name_or_v4(host_text: str) -> tuple[str, IPv4Address | None]:
    text = host_text
    if not text.isascii():
        if any(ch in _DEVIATIONS for ch in text):
            raise TargetParseError("idna")
        text = unicodedata.normalize("NFKC", text).replace("。", ".")
        # SEC-A5: the whole reject set runs again on the post-NFKC text.
        _reject_chars(text)
        if any(ch in _META_AFTER_NFKC for ch in text):
            raise TargetParseError("charset")
        try:
            text = text.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise TargetParseError("idna") from exc
    text = text.lower()
    if text.endswith("."):
        text = text[:-1]
        if text.endswith("."):
            raise TargetParseError("dots")
    if not text:
        raise TargetParseError("host")
    labels = text.split(".")
    for label in labels:
        if not _LABEL_RE.fullmatch(label):
            raise TargetParseError("label")
    if len(text) > MAX_HOST_LEN:
        raise TargetParseError("hostlen")
    for label in labels:
        if label.startswith("xn--"):
            _check_punycode(label)
    if _NUMERIC_LAST_RE.fullmatch(labels[-1]):
        ip4 = _parse_ipv4_numeric(labels)
        return str(ip4), ip4
    return text, None


def _parse_ipv6(host_text: str) -> IPAddress:
    if not host_text.isascii():
        raise TargetParseError("ipv6")
    try:
        ip6 = IPv6Address(host_text)
    except ValueError as exc:
        raise TargetParseError("ipv6") from exc
    return _collapse_mapped(ip6)


def parse_host_literal(text: str) -> tuple[str, IPAddress | None]:
    """Canonicalise a bare host or IP literal (no scheme, port, path).

    Used for scope entries. Raises :class:`TargetParseError` only.
    """
    if not isinstance(text, str):
        raise TypeError("host text must be str")
    if not text or len(text) > MAX_TARGET_LEN:
        raise TargetParseError("length")
    _reject_chars(text)
    if ":" in text:
        ip = _parse_ipv6(text)
        return str(ip), ip
    host, ip4 = _canonical_name_or_v4(text)
    return host, ip4


def canonical_target(raw: str) -> CanonicalTarget:
    if not isinstance(raw, str):
        raise TypeError("target must be str")
    if not raw or len(raw) > MAX_TARGET_LEN:
        raise TargetParseError("length")
    _reject_chars(raw)
    if raw.startswith("//"):
        raise TargetParseError("scheme")
    scheme: Literal["http", "https"] | None = None
    rest = raw
    idx = rest.find("://")
    if idx >= 0:
        name = rest[:idx].lower()
        if name == "http":
            scheme = "http"
        elif name == "https":
            scheme = "https"
        else:
            raise TargetParseError("scheme")
        rest = rest[idx + 3 :]
    end = _AUTHORITY_END_RE.search(rest)
    authority = rest[: end.start()] if end else rest
    tail = rest[end.start() :] if end else ""
    if not authority:
        raise TargetParseError("host")
    if "@" in authority:
        raise TargetParseError("userinfo")

    port_text: str | None = None
    host_text = authority
    is_v6 = False
    if authority.startswith("["):
        close = authority.find("]")
        if close < 0:
            raise TargetParseError("ipv6")
        host_text = authority[1:close]
        after = authority[close + 1 :]
        if after:
            if not after.startswith(":"):
                raise TargetParseError("ipv6")
            port_text = after[1:]
        if ":" not in host_text:
            raise TargetParseError("ipv6")
        is_v6 = True
    else:
        colons = authority.count(":")
        if colons == 1:
            host_text, port_text = authority.split(":", 1)
        elif colons >= 2:
            is_v6 = True

    port: int | None = None
    if port_text is not None:
        if not _PORT_RE.fullmatch(port_text):
            raise TargetParseError("port")
        port = int(port_text, 10)
        if not 1 <= port <= 65535:
            raise TargetParseError("port")

    host: str
    ip: IPAddress | None
    if is_v6:
        ip = _parse_ipv6(host_text)
        host = str(ip)
    else:
        host, ip = _canonical_name_or_v4(host_text)

    if ip is not None and scheme is None and _CIDR_PATH_RE.fullmatch(tail):
        raise TargetParseError("cidr_target")
    if port is None and scheme is not None:
        port = 80 if scheme == "http" else 443
    return CanonicalTarget(host=host, ip=ip, port=port, scheme=scheme)


def canonical_ip(text: str) -> IPAddress:
    """Strict resolver-output parser: dotted quad or RFC 4291 text only."""
    if not isinstance(text, str) or not text.isascii() or "%" in text:
        raise ValueError("not an IP literal")
    return _collapse_mapped(ipaddress.ip_address(text))


def embedded_ipv4_candidates(ip: IPAddress) -> tuple[IPv4Address, ...]:
    """IPv4 addresses embedded in an IPv6 address (mapped, NAT64, 6to4, compat)."""
    if isinstance(ip, IPv4Address):
        return ()
    value = int(ip)
    out: list[IPv4Address] = []
    mapped = ip.ipv4_mapped
    if mapped is not None:
        out.append(mapped)
    if ip in _NAT64:
        out.append(IPv4Address(value & 0xFFFFFFFF))
    if ip in _SIXTO4:
        out.append(IPv4Address((value >> 80) & 0xFFFFFFFF))
    if ip in _COMPAT and value > 1:
        out.append(IPv4Address(value & 0xFFFFFFFF))
    return tuple(out)


def embedded_ipv4_networks(net: IPNetwork) -> tuple[IPv4Network, ...]:
    """IPv4 networks that the embedded addresses of an IPv6 network can take."""
    if isinstance(net, IPv4Network):
        return ()
    out: list[IPv4Network] = []
    for base, shift in ((_MAPPED, 0), (_NAT64, 0), (_SIXTO4, 80), (_COMPAT, 0)):
        if not net.overlaps(base):
            continue
        if net.prefixlen <= base.prefixlen:
            out.append(_ALL_V4)
            continue
        bits = min(32, net.prefixlen - base.prefixlen)
        v4 = (int(net.network_address) >> shift) & 0xFFFFFFFF
        mask = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
        out.append(IPv4Network((v4 & mask, bits)))
    return tuple(dict.fromkeys(out))
