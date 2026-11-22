"""compile_scope accepted and rejected entry forms (design section 3)."""

from __future__ import annotations

import ipaddress as ip

import pytest

from vulnscope.policy.scope import ScopeEntryError, compile_scope, host_matches, ip_matches
from vulnscope.policy.target import canonical_target


def T(raw: str):  # noqa: N802
    return canonical_target(raw)


def test_accepted_forms() -> None:
    s = compile_scope(
        [
            "10.0.0.0/8",
            "192.0.2.7",
            "0x7f.1",
            "fd00::/8",
            "2001:db8::5",
            "Lab.Test.",
            "*.Example.Test",
        ]
    )
    assert ip.ip_network("10.0.0.0/8") in s.nets
    assert ip.ip_network("192.0.2.7/32") in s.nets
    assert ip.ip_network("127.0.0.1/32") in s.nets
    assert ip.ip_network("2001:db8::5/128") in s.nets
    assert s.exact_hosts == frozenset({"lab.test"})
    assert s.wildcard_suffixes == ("example.test",)


@pytest.mark.parametrize(
    "entry",
    [
        "",
        "*",
        "*.com",
        "*.",
        "a*.lab.test",
        "*.*.lab.test",
        "lab.*.test",
        "http://lab.test",
        "lab.test:80",
        "lab.test/path",
        "10.0.0.1/8",
        "10.0.0.0/33",
        "300.1.1.1/8",
        " lab.test",
        "lab test",
        "*.0x7f.1",
        "[::1]",
        "a@b",
        "lab.test\n",
        "fe80::1%eth0",
    ],
)
def test_rejected_forms(entry: str) -> None:
    with pytest.raises(ScopeEntryError) as info:
        compile_scope([entry])
    assert info.value.code.isascii()
    assert entry not in str(info.value) or entry == ""


def test_scope_entry_error_is_value_error() -> None:
    assert issubclass(ScopeEntryError, ValueError)


def test_wildcard_depth_and_apex() -> None:
    s = compile_scope(["*.lab.test"])
    assert host_matches(s, T("a.lab.test"))
    assert host_matches(s, T("a.b.c.lab.test"))
    assert not host_matches(s, T("lab.test"))
    assert not host_matches(s, T("xlab.test"))
    assert not host_matches(s, T("lab.test.evil.test"))


def test_exact_entry_does_not_cascade() -> None:
    s = compile_scope(["lab.test"])
    assert host_matches(s, T("LAB.TEST."))
    assert not host_matches(s, T("sub.lab.test"))


def test_hostname_not_covered_by_cidr_and_literal_covered() -> None:
    s = compile_scope(["10.0.0.0/8"])
    assert not host_matches(s, T("host.lab.test"))
    assert host_matches(s, T("10.1.2.3"))
    assert host_matches(s, T("0x0a.1"))
    assert ip_matches(s, ip.ip_address("10.9.9.9"))
    assert not ip_matches(s, ip.ip_address("11.0.0.1"))


def test_caps() -> None:
    with pytest.raises(ScopeEntryError) as e1:
        compile_scope([f"h{i}.test" for i in range(257)])
    assert e1.value.code == "too_many"
    compile_scope([f"h{i}.test" for i in range(256)])
    with pytest.raises(ScopeEntryError) as e2:
        compile_scope(["a" * 254])
    assert e2.value.code == "too_long"


def test_non_str_entry_is_a_type_error() -> None:
    with pytest.raises(TypeError):
        compile_scope([5])  # type: ignore[list-item]


def test_expected_accepts_networks_only() -> None:
    s = compile_scope(["192.0.2.0/24", "203.0.113.9"], "expected")
    assert len(s.nets) == 2
    for bad in (
        ["lab.test"],
        ["*.lab.test"],
        [""],
        ["http://192.0.2.1"],
        ["192.0.2.1:80"],
        ["192.0.2.1/24"],
        ["192.0.2.1/x"],
    ):
        with pytest.raises(ScopeEntryError) as info:
            compile_scope(bad, "expected")
        assert info.value.code == "expected_not_network"


def test_slash_zero_is_accepted_by_compile() -> None:
    s = compile_scope(["0.0.0.0/0", "::/0"])
    assert ip_matches(s, ip.ip_address("8.8.8.8"))
    assert ip_matches(s, ip.ip_address("2001:db8::1"))


def test_mapped_all_is_everything_ipv4() -> None:
    s = compile_scope(["::ffff:0:0/96"])
    assert ip_matches(s, ip.ip_address("8.8.8.8"))
