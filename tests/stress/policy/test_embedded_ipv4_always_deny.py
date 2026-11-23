"""Stress (R1): embedded-IPv4 ranges are ALWAYS-DENY (owner decision, task-a-design.md 11.3 plus the
2026-11-23 amendment): NAT64 64:ff9b::/96, 6to4 2002::/16 and IPv4-compatible ::/96 deny by range,
whatever IPv4 they embed, with ``::1`` and ``::`` carved out (``::`` is already D7; ``::1`` is governed
by the profile: lab allows it, standard answers DENY_PRIVATE_RANGE as before).

Matrix: embedded 10.0.0.1, 127.0.0.1, 169.254.169.254, 100.64.0.1 x every notation (dotted, hex,
expanded, upper, mixed case) x target kind (bare literal, bracketed literal, hostname whose resolver
answer is the literal) x scope.allow (open ``0.0.0.0/0, ::/0`` and the exact CIDR of the embedded
address plus the target itself) x profile (standard, lab). Expected: DENY_ALWAYS_LIST every time,
and no resolver call for literals. Boundary rows for each new range and for the six SEC-A15 ranges
(values from task-a-design.md 11.3; 64:ff9b::808:808 flips to DENY by the newer owner decision).
Addresses are RFC-reserved or documentation space; no network I/O (fake resolver and clock).
"""
# ruff: noqa: E501
from __future__ import annotations

import ipaddress
from datetime import UTC, datetime

import pytest

from vulnscope.policy.decide import decide
from vulnscope.policy.ratelimit import InMemoryRateLimitStore
from vulnscope.policy.types import Action, RuleId

OPEN = ("0.0.0.0/0", "::/0")
EMBEDDED = {
    "10.0.0.1": "10.0.0.0/8",
    "127.0.0.1": "127.0.0.0/8",
    "169.254.169.254": "169.254.0.0/16",
    "100.64.0.1": "100.64.0.0/10",
}
NOW = datetime(2026, 1, 15, tzinfo=UTC)


def _mix(text: str) -> str:
    """Alternate case over letters only (mixed-case notation)."""
    out, flip = [], False
    for ch in text:
        if ch.isalpha():
            out.append(ch.upper() if flip else ch.lower())
            flip = not flip
        else:
            out.append(ch)
    return "".join(out)


def forms(v4: str) -> dict[str, str]:
    a, b, c, d = (int(p) for p in v4.split("."))
    hi, lo = (a << 8) | b, (c << 8) | d
    x, y, xx, yy = f"{hi:x}", f"{lo:x}", f"{hi:04x}", f"{lo:04x}"
    n64 = f"64:ff9b::{x}:{y}"
    s4 = f"2002:{x}:{y}::1"
    cp = f"::{x}:{y}"
    return {
        "nat64_dotted": f"64:ff9b::{v4}",
        "nat64_dotted_expanded": f"0064:ff9b:0000:0000:0000:0000:{v4}",
        "nat64_hex": n64,
        "nat64_expanded": f"0064:ff9b:0000:0000:0000:0000:{xx}:{yy}",
        "nat64_upper": n64.upper(),
        "nat64_mixed": _mix(n64),
        "6to4_bare": f"2002:{x}:{y}::",
        "6to4_host": s4,
        "6to4_expanded": f"2002:{xx}:{yy}:0000:0000:0000:0000:0001",
        "6to4_upper": s4.upper(),
        "6to4_mixed": _mix(s4),
        "compat_dotted": f"::{v4}",
        "compat_hex": cp,
        "compat_expanded": f"0000:0000:0000:0000:0000:0000:{xx}:{yy}",
        "compat_upper": cp.upper(),
        "compat_mixed": _mix(cp),
    }


CASES = [(v4, name, text) for v4 in EMBEDDED for name, text in forms(v4).items()]
IDS = [f"{v4}-{name}" for v4, name, _ in CASES]


class _Resolver:
    def __init__(self, table):
        self.table, self.calls = table, []

    def resolve(self, hostname):
        self.calls.append(hostname)
        return self.table[hostname]


class _Clock:
    def now(self):
        return NOW

    def monotonic(self):
        return 0.0


def run(engagement_factory, target, *, allow, answers=None, profile="standard", lab=None):
    from datetime import timedelta

    engagement = engagement_factory(
        scope_allow=allow, profile=profile,
        window_not_before=NOW - timedelta(days=1), window_not_after=NOW + timedelta(days=1),
    )
    resolver = _Resolver(answers or {})
    kw = {"lab_enabled": True, "lab_cidr": lab} if profile == "lab" else {}
    d = decide(Action(kind="http", target=target, adapter="stress-test"), engagement, NOW,
               resolver=resolver, clock=_Clock(), rate_limit_store=InMemoryRateLimitStore(), **kw)
    return d, resolver


def _is_always_deny(d) -> bool:
    return (not d.allowed) and d.rule_id == RuleId.DENY_ALWAYS_LIST


PROFILES = [("standard", None), ("lab", "10.0.0.0/8")]


@pytest.mark.parametrize("profile,lab", PROFILES, ids=["standard", "lab"])
@pytest.mark.parametrize("allow_kind", ["open", "exact_cidr"])
@pytest.mark.parametrize("v4,name,text", CASES, ids=IDS)
def test_embedded_ipv4_literal_is_always_denied(engagement_factory, v4, name, text, allow_kind, profile, lab) -> None:
    canonical = str(ipaddress.ip_address(text))
    allow = OPEN if allow_kind == "open" else (EMBEDDED[v4], canonical)
    for target in (text, f"[{text}]"):
        d, resolver = run(engagement_factory, target, allow=allow, profile=profile, lab=lab)
        assert _is_always_deny(d), f"{target!r}: expected DENY_ALWAYS_LIST, got allowed={d.allowed} rule={d.rule_id}"
        assert resolver.calls == [], "an IP literal must never reach the resolver"


@pytest.mark.parametrize("profile,lab", PROFILES, ids=["standard", "lab"])
@pytest.mark.parametrize("allow_kind", ["open", "exact_cidr"])
@pytest.mark.parametrize("v4,name,text", CASES, ids=IDS)
def test_embedded_ipv4_resolver_answer_is_always_denied(engagement_factory, v4, name, text, allow_kind, profile, lab) -> None:
    host = "embedded.lab.test"
    canonical = str(ipaddress.ip_address(text))
    allow = (*OPEN, host) if allow_kind == "open" else (EMBEDDED[v4], canonical, host)
    d, resolver = run(engagement_factory, host, allow=allow, answers={host: (text,)}, profile=profile, lab=lab)
    assert _is_always_deny(d), f"answer {text!r}: expected DENY_ALWAYS_LIST, got allowed={d.allowed} rule={d.rule_id}"
    assert resolver.calls == [host]


@pytest.mark.parametrize("v4", sorted(EMBEDDED))
def test_one_embedded_answer_among_clean_ones_denies_the_whole_answer_set(engagement_factory, v4) -> None:
    host = "mixed.lab.test"
    for answers in ((  "192.0.2.1", forms(v4)["nat64_hex"]), (forms(v4)["6to4_host"], "2001:db8::1")):
        d, _ = run(engagement_factory, host, allow=(*OPEN, host), answers={host: answers})
        assert _is_always_deny(d)


# ------------------------------------------------------------------ carve-outs and clean controls
def test_ipv6_loopback_is_governed_by_the_profile_not_the_embedded_range(engagement_factory) -> None:
    for target in ("::1", "[::1]", "0:0:0:0:0:0:0:1", "0000:0000:0000:0000:0000:0000:0000:0001"):
        d, _ = run(engagement_factory, target, allow=OPEN)
        assert not d.allowed and d.rule_id == RuleId.DENY_PRIVATE_RANGE, f"standard {target!r}"
        for allow in (OPEN, ("::1",)):
            d, _ = run(engagement_factory, target, allow=allow, profile="lab", lab="10.0.0.0/8")
            assert d.allowed and d.rule_id == RuleId.ALLOW, f"lab {target!r} allow={allow}"
        d, _ = run(engagement_factory, target, allow=("::1",), profile="lab", lab=None)
        assert d.allowed and d.rule_id == RuleId.ALLOW


def test_ipv6_loopback_by_name_in_lab_is_allowed(engagement_factory) -> None:
    host = "loop6.lab.test"
    d, _ = run(engagement_factory, host, allow=(host,), answers={host: ("::1",)}, profile="lab", lab=None)
    assert d.allowed and d.rule_id == RuleId.ALLOW


def test_unspecified_address_stays_always_denied_in_every_profile(engagement_factory) -> None:
    for profile, lab in PROFILES:
        d, _ = run(engagement_factory, "::", allow=OPEN, profile=profile, lab=lab)
        assert _is_always_deny(d)


def test_clean_public_ipv6_stays_allowed(engagement_factory) -> None:
    host = "clean6.lab.test"
    for target in ("2001:db8::1", "[2001:db8::1]", "2001:0db8:0000:0000:0000:0000:0000:0001", "2001:DB8::1"):
        d, resolver = run(engagement_factory, target, allow=OPEN)
        assert d.allowed and d.rule_id == RuleId.ALLOW and resolver.calls == [], target
    d, _ = run(engagement_factory, host, allow=(*OPEN, host), answers={host: ("2001:db8::1",)})
    assert d.allowed and d.rule_id == RuleId.ALLOW and d.resolved_ips == ("2001:db8::1",)


# ------------------------------------------------------------------ boundaries (standard profile, open allow)
DENY_ROWS = [
    # new embedded ranges (owner decision 2026-11-23): first and last address of each range
    "64:ff9b::", "64:ff9b::1", "64:ff9b::808:808", "64:ff9b::ffff:ffff", "64:ff9b::0.0.0.1",
    "2002::", "2002::1", "2002:808:808::1", "2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
    "::2", "::0.0.0.2", "::808:808", "::ffff:ffff", "::255.255.255.255",
    # SEC-A15 ranges, task-a-design.md 11.3
    "2001::", "2001::5601:5601", "2001:0:ffff:ffff:ffff:ffff:ffff:ffff",
    "::ffff:0:a9fe:a9fe", "::ffff:0:0.0.0.1", "::ffff:0:ffff:ffff",
    "192.0.0.0", "192.0.0.192", "192.0.0.255",
    "240.0.0.0", "247.1.2.3", "255.255.255.254",
    "fec0::", "fec0::1", "feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
    "64:ff9b:1::", "64:ff9b:1:ffff:ffff:ffff:ffff:ffff",
]
ALLOW_ROWS = [
    # just outside the new embedded ranges
    "64:ff9b:0:1::", "64:ff9b::1:0:0", "64:ff9b:2::", "2001:ffff::", "2003::", "2001:1::",
    "::1:0:0", "::ffff:1:0:0",
    # just outside the SEC-A15 ranges (11.3) and mapped handling intact
    "2000:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "2001:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
    "191.255.255.255", "192.0.1.0", "192.0.2.1", "223.255.255.255", "::ffff:8.8.8.8", "2001:db8::1",
    # 198.18.0.0/15 stays OUT of the list (owner decision)
    "198.18.0.1", "198.19.255.255",
]


@pytest.mark.parametrize("target", DENY_ROWS)
def test_boundary_deny_rows(engagement_factory, target) -> None:
    d, resolver = run(engagement_factory, target, allow=OPEN)
    assert _is_always_deny(d), f"{target}: allowed={d.allowed} rule={d.rule_id}"
    assert resolver.calls == []


@pytest.mark.parametrize("target", ALLOW_ROWS)
def test_boundary_allow_rows(engagement_factory, target) -> None:
    d, _ = run(engagement_factory, target, allow=OPEN)
    assert d.allowed and d.rule_id == RuleId.ALLOW, f"{target}: allowed={d.allowed} rule={d.rule_id}"
