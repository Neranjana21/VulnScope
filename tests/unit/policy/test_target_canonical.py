"""Golden-table tests for policy/target.py (design section 3, STR-A2 corpus)."""

from __future__ import annotations

import ipaddress

import pytest
from target_corpus import ACCEPT, LOOPBACK_ENCODINGS, METADATA_ENCODINGS, REJECT

from vulnscope.policy.target import (
    CanonicalTarget,
    TargetParseError,
    canonical_ip,
    canonical_target,
)


@pytest.mark.parametrize(("raw", "host", "port", "scheme"), ACCEPT)
def test_accept_rows(raw: str, host: str, port: int | None, scheme: str | None) -> None:
    t = canonical_target(raw)
    assert isinstance(t, CanonicalTarget)
    assert t.host == host
    assert t.port == port
    assert t.scheme == scheme
    if t.ip is not None:
        assert t.host == str(t.ip)
    else:
        assert t.host.isascii()


@pytest.mark.parametrize(("raw", "code"), REJECT)
def test_reject_rows(raw: str, code: str) -> None:
    with pytest.raises(TargetParseError) as info:
        canonical_target(raw)
    assert info.value.code == code
    # the stable code never echoes the raw input
    assert raw not in str(info.value) or raw == ""
    assert str(info.value).isascii()


@pytest.mark.parametrize("raw", [r for r, *_ in ACCEPT])
def test_idempotent(raw: str) -> None:
    first = canonical_target(raw)
    again = canonical_target(first.host)
    assert again.host == first.host
    assert again.ip == first.ip


@pytest.mark.parametrize("raw", LOOPBACK_ENCODINGS)
def test_loopback_encodings_collapse(raw: str) -> None:
    assert canonical_target(raw).ip == ipaddress.IPv4Address("127.0.0.1")


@pytest.mark.parametrize("raw", METADATA_ENCODINGS)
def test_metadata_encodings_collapse(raw: str) -> None:
    assert canonical_target(raw).ip == ipaddress.IPv4Address("169.254.169.254")


def test_host_case_and_trailing_dot_do_not_split_identity() -> None:
    assert canonical_target("HOST.").host == canonical_target("host").host == "host"


def test_userinfo_variants_never_parse_to_the_decoy_host() -> None:
    for raw in (
        "http://allowed.test@evil.test",
        "http://evil.test\\@allowed.test",
        "http://evil.test%40allowed.test",
    ):
        with pytest.raises(TargetParseError):
            canonical_target(raw)
    # '#' ends the authority, so the true host is evil.test and nothing else
    assert canonical_target("http://evil.test#@allowed.test").host == "evil.test"


def test_long_input_is_cheap_and_rejected() -> None:
    with pytest.raises(TargetParseError) as info:
        canonical_target("a" * 1_000_000)
    assert info.value.code == "length"


def test_canonical_ip_strict() -> None:
    assert canonical_ip("::ffff:10.1.2.3") == ipaddress.IPv4Address("10.1.2.3")
    assert canonical_ip("192.0.2.1") == ipaddress.IPv4Address("192.0.2.1")
    for bad in (
        "fe80::1%eth0",
        "127.1",
        "0x7f.1",
        "2130706433",
        " 1.2.3.4",
        "1.2.3.4\n",
        "",
        "x",
        "010.0.0.1",
        "1.2.3",
    ):
        with pytest.raises(ValueError):
            canonical_ip(bad)
    with pytest.raises(ValueError):
        canonical_ip(5)  # type: ignore[arg-type]
