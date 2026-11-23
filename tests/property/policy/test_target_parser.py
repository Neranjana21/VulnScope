"""Property tests for the canonical parser and decide() (design section 6)."""

from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime, timedelta

from hypothesis import given, settings
from hypothesis import strategies as st

from vulnscope.policy.decide import decide
from vulnscope.policy.denylist import ALWAYS_DENY_NETWORKS
from vulnscope.policy.ratelimit import InMemoryRateLimitStore
from vulnscope.policy.target import TargetParseError, canonical_target
from vulnscope.policy.types import Action, EngagementPolicyView, RuleId

NOW = datetime(2026, 1, 15, tzinfo=UTC)
START = datetime(2026, 1, 1, tzinfo=UTC)


class _Clock:
    def now(self) -> datetime:
        return NOW

    def monotonic(self) -> float:
        return 0.0


class _NoResolver:
    def __init__(self) -> None:
        self.calls = 0

    def resolve(self, hostname: str) -> tuple[str, ...]:
        self.calls += 1
        return ("192.0.2.1",)


def _decide(target: str, allow=("0.0.0.0/0", "::/0"), deny=(), profile="standard", **kw):
    view = EngagementPolicyView(
        engagement_id="eng-1",
        org_id="org",
        profile=profile,
        status="active",
        scope_allow=tuple(allow),
        scope_deny=tuple(deny),
        expected_ip_ranges=(),
        rate_limit_rps=1e6,
        window_not_before=START,
        window_not_after=START + timedelta(days=60),
        policy_version="1.0.0+prop",
    )
    res = _NoResolver()
    d = decide(
        Action("http", target, "prop"),
        view,
        NOW,
        resolver=res,
        clock=_Clock(),
        rate_limit_store=InMemoryRateLimitStore(),
        **kw,
    )
    return d, res


def _v4_encodings(value: int) -> list[str]:
    a, b, c, d = value >> 24, (value >> 16) & 255, (value >> 8) & 255, value & 255
    dotted = f"{a}.{b}.{c}.{d}"
    return [
        dotted,
        f"{a}.{b}.{c}.{d}.",
        str(value),
        hex(value),
        hex(value).upper().replace("0X", "0x"),
        f"{a}.{b}.{(c << 8) | d}",
        f"{a}.{(b << 16) | (c << 8) | d}",
        f"0{a:o}.0{b:o}.0{c:o}.0{d:o}",
        f"0x{a:x}.0x{b:x}.0x{c:x}.0x{d:x}",
        f"0x{a:x}.{b}.0{c:o}.{d}",
        "".join(chr(0xFF10 + int(ch)) if ch.isdigit() else "．" for ch in dotted),
        f"[::ffff:{value >> 16:x}:{value & 0xFFFF:x}]",
        f"::ffff:{dotted}",
        f"[::FFFF:{value >> 16:X}:{value & 0xFFFF:X}]",
        f"[0:0:0:0:0:ffff:{dotted}]",
    ]


@given(
    st.integers(0, 2**32 - 1),
    st.sampled_from(["", "http://", "https://", "HTTP://"]),
    st.sampled_from(["", ":80", ":8443"]),
    st.sampled_from(["", "/", "/x?y#z"]),
)
@settings(max_examples=300, deadline=None)
def test_all_encodings_give_the_same_canonical_ip(
    value: int, scheme: str, port: str, path: str
) -> None:
    want = ipaddress.IPv4Address(value)
    for enc in _v4_encodings(value):
        bare_v6 = enc.startswith("::")
        raw = f"{scheme}{enc}{'' if bare_v6 else port}{path}"
        assert canonical_target(raw).ip == want, raw


@given(st.integers(0, 2**32 - 1))
@settings(max_examples=200, deadline=None)
def test_decide_equal_across_encodings(value: int) -> None:
    base, _ = _decide(str(ipaddress.IPv4Address(value)))
    for enc in _v4_encodings(value):
        d, res = _decide(enc)
        assert (d.rule_id, d.resolved_ips) == (base.rule_id, base.resolved_ips), enc
        assert res.calls == 0


_NETS = [n for n in ALWAYS_DENY_NETWORKS]


@given(st.sampled_from(_NETS), st.data(), st.sampled_from(["standard", "lab"]))
@settings(max_examples=300, deadline=None)
def test_any_always_deny_address_is_denied_under_every_encoding(net, data, profile) -> None:
    offset = data.draw(st.integers(0, net.num_addresses - 1))
    addr = net[offset]
    lab = {"lab_enabled": True, "lab_cidr": "10.0.0.0/8"} if profile == "lab" else {}
    targets = [str(addr)]
    if addr.version == 4:
        targets += _v4_encodings(int(addr))
    else:
        targets.append(f"[{addr}]")
    for t in targets:
        d, res = _decide(t, profile=profile, **lab)
        assert d.rule_id == RuleId.DENY_ALWAYS_LIST, (t, d.rule_id)
        assert not d.allowed and res.calls == 0


@given(st.text())
@settings(max_examples=500, deadline=None)
def test_parser_and_decide_never_raise_on_text(text: str) -> None:
    try:
        t = canonical_target(text)
    except TargetParseError as exc:
        assert re.fullmatch(r"[a-z_0-9]+", exc.code)
    else:
        again = canonical_target(t.host)
        assert again.host == t.host and again.ip == t.ip  # idempotent
    d, _ = _decide(text)
    assert d.action.target == text
    if d.allowed:
        t = canonical_target(text)
        assert t.ip is None or ipaddress.ip_address(d.resolved_ips[0]) == t.ip


def _controlish() -> st.SearchStrategy[str]:
    alphabet = st.sampled_from(list("ab.:/@#?%\\ \t\n\x00[]0x1") + ["‮", "​", "＠"])
    return st.text(alphabet, max_size=24)


@given(_controlish())
@settings(max_examples=500, deadline=None)
def test_control_heavy_input_only_raises_parse_errors(text: str) -> None:
    try:
        canonical_target(text)
    except TargetParseError:
        pass


@given(
    st.sampled_from(["a.test", "1.2.3.4", "h.example"]),
    st.sampled_from(["@", "\\", "%", "%25", "\t", " ", "‮", "＠", "​"]),
)
@settings(max_examples=100, deadline=None)
def test_userinfo_backslash_percent_whitespace_always_reject(host: str, bad: str) -> None:
    for raw in (f"{host}{bad}x", f"u{bad}{host}", f"http://u{bad}{host}"):
        try:
            canonical_target(raw)
        except TargetParseError:
            continue
        raise AssertionError(raw)


@given(st.sampled_from(["a.test", "1.2.3.4"]), st.integers(1, 5))
@settings(max_examples=30, deadline=None)
def test_extra_trailing_dots_reject(host: str, n: int) -> None:
    try:
        canonical_target(host + "." * (n + 1))
    except TargetParseError:
        return
    raise AssertionError("two or more trailing dots must reject")


def _ref_covers(host: str, entries: list[str]) -> bool:
    """Independent tiny reference matcher (does not import scope.py)."""
    for e in entries:
        if e.startswith("*."):
            if host.endswith(e[1:]):
                return True
        elif "/" in e:
            try:
                if ipaddress.ip_address(host) in ipaddress.ip_network(e):
                    return True
            except ValueError:
                pass
        elif e == host:
            return True
    return False


@given(st.text(max_size=30))
@settings(max_examples=400, deadline=None)
def test_allowed_implies_reference_matcher_agrees(text: str) -> None:
    allow = ["*.lab.test", "192.0.2.0/24", "ok.example"]
    deny = ["bad.lab.test", "192.0.2.128/25"]
    d, _ = _decide(text, allow=allow, deny=deny)
    if d.allowed:
        host = canonical_target(text).host
        assert _ref_covers(host, allow) and not _ref_covers(host, deny)
