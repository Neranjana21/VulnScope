"""Property tests: deny wins, monotonicity, union semantics for CIDR sets."""

from __future__ import annotations

import ipaddress as ip

from hypothesis import given, settings
from hypothesis import strategies as st

from vulnscope.policy.scope import compile_scope, ip_matches

v4net = st.builds(
    lambda a, p: ip.IPv4Network((a >> (32 - p) << (32 - p), p)),
    st.integers(0, 2**32 - 1),
    st.integers(0, 32),
)
v4addr = st.builds(ip.IPv4Address, st.integers(0, 2**32 - 1))


@given(st.lists(v4net, max_size=8), st.lists(v4net, max_size=8), v4addr)
@settings(max_examples=300, deadline=None)
def test_union_semantics_and_deny_wins(allow, deny, addr) -> None:
    a = compile_scope([str(n) for n in allow])
    d = compile_scope([str(n) for n in deny])
    in_allow = any(addr in n for n in allow)
    in_deny = any(addr in n for n in deny)
    assert ip_matches(a, addr) == in_allow
    assert ip_matches(d, addr) == in_deny
    permitted = ip_matches(a, addr) and not ip_matches(d, addr)
    assert permitted == (in_allow and not in_deny)


@given(st.lists(v4net, max_size=6), v4net, v4addr)
@settings(max_examples=300, deadline=None)
def test_adding_a_deny_entry_never_turns_a_deny_into_an_allow(allow, extra, addr) -> None:
    deny = []
    a = compile_scope([str(n) for n in allow])
    before = ip_matches(a, addr) and not ip_matches(compile_scope([str(n) for n in deny]), addr)
    deny.append(extra)
    after = ip_matches(a, addr) and not ip_matches(compile_scope([str(n) for n in deny]), addr)
    assert (not before) <= (not after)  # False before implies False after
    assert not (after and not before)
