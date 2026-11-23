"""SEC-A2: mapped-network spellings equal the IPv4 form in allow, deny, expected."""

from __future__ import annotations

import ipaddress as ip

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from policy_test_support import make_view, run_decide

from vulnscope.policy.scope import ScopeEntryError, compile_scope, ip_matches
from vulnscope.policy.types import RuleId

SPELLINGS = (
    "::ffff:10.1.0.0/112",
    "::ffff:a01:0/112",
    "0:0:0:0:0:ffff:a01:0/112",
    "0000:0000:0000:0000:0000:FFFF:0A01:0000/112",
    "::FFFF:A01:0/112",
)


@pytest.mark.parametrize("entry", SPELLINGS)
def test_spellings_collapse_to_ipv4(entry: str) -> None:
    s = compile_scope([entry])
    assert s.nets == (ip.ip_network("10.1.0.0/16"),)


@pytest.mark.parametrize("kind", ["allow", "deny", "expected"])
@pytest.mark.parametrize("entry", SPELLINGS)
def test_each_kind_collapses(kind: str, entry: str) -> None:
    s = compile_scope([entry], kind)  # type: ignore[arg-type]
    assert ip_matches(s, ip.ip_address("10.1.2.3"))
    assert not ip_matches(s, ip.ip_address("10.2.0.1"))


def test_single_mapped_ip_collapses() -> None:
    assert compile_scope(["::ffff:10.1.2.3"]).nets == (ip.ip_network("10.1.2.3/32"),)


def test_mapped_whole_block_is_all_ipv4() -> None:
    assert compile_scope(["::ffff:0:0/96"]).nets == (ip.ip_network("0.0.0.0/0"),)


def test_mapped_deny_excludes_literal_and_resolved() -> None:
    decision, _ = run_decide("10.1.2.3", allow=("10.0.0.0/8",), deny=("::ffff:10.1.0.0/112",))
    assert decision.rule_id == RuleId.EXCLUDED
    decision, _ = run_decide(
        "h.lab.test",
        allow=("h.lab.test", "10.0.0.0/8"),
        deny=("::ffff:a01:0/112",),
        table={"h.lab.test": ("10.1.2.3",)},
    )
    assert decision.rule_id == RuleId.EXCLUDED


def test_mapped_prefix_below_96_raises() -> None:
    with pytest.raises(ScopeEntryError):
        compile_scope(["::ffff:10.1.0.0/80"])
    with pytest.raises(ScopeEntryError):
        compile_scope(["::ffff:0:0/95"])


def test_malformed_expected_ranges_raise_at_view_construction() -> None:
    with pytest.raises(ScopeEntryError):
        make_view(expected_ip_ranges=("not-a-net",))
    with pytest.raises(ScopeEntryError):
        make_view(expected_ip_ranges=("lab.test",))


def test_expected_mapped_spelling_enforced() -> None:
    decision, _ = run_decide(
        "h.lab.test",
        allow=("h.lab.test",),
        expected_ip_ranges=("::ffff:192.0.2.0/120",),
        table={"h.lab.test": ("198.51.100.1",)},
    )
    assert decision.rule_id == RuleId.RESOLVED_OUTSIDE_EXPECTED
    decision, _ = run_decide(
        "h.lab.test",
        allow=("h.lab.test",),
        expected_ip_ranges=("::ffff:192.0.2.0/120",),
        table={"h.lab.test": ("192.0.2.9",)},
    )
    assert decision.allowed


@given(st.integers(0, 2**32 - 1), st.integers(8, 32))
@settings(max_examples=200, deadline=None)
def test_exclusion_holds_under_all_spellings(addr: int, prefix: int) -> None:
    net4 = ip.IPv4Network((addr >> (32 - prefix) << (32 - prefix), prefix))
    mapped = ip.IPv6Network(((0xFFFF << 32 | int(net4.network_address)) << 0, 96 + prefix))
    s4 = compile_scope([str(net4)])
    s6 = compile_scope([str(mapped)])
    probe = ip.IPv4Address(int(net4.network_address) + (int(net4.num_addresses) - 1) // 2)
    assert ip_matches(s4, probe) and ip_matches(s6, probe)
    assert s4.nets == s6.nets
