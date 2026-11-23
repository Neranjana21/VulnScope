"""AC1 / SEC-2: no DNS lookup before the target is authorised."""

from __future__ import annotations

from datetime import timedelta

import pytest
from policy_test_support import WINDOW_END, WINDOW_START, run_decide

H = "a.lab.test"
TABLE = {H: ("192.0.2.1",)}


@pytest.mark.parametrize(
    "kwargs",
    [
        dict(allow=(H,), status="revoked"),
        dict(allow=(H,), now=WINDOW_END + timedelta(seconds=1)),
        dict(allow=(H,), now=WINDOW_START - timedelta(seconds=1)),
        dict(allow=(H,), deny=(H,)),
        dict(allow=("*.lab.test",), deny=("*.lab.test",)),
        dict(allow=("other.lab.test",)),
        dict(allow=("10.0.0.0/8",)),
        dict(allow=()),
        dict(allow=(H,), profile="lab"),
        dict(allow=(H,), lab_enabled=True, lab_cidr="garbage"),
    ],
)
def test_zero_lookups_when_denied_before_resolution(kwargs: dict) -> None:
    d, resolver = run_decide(H, table=TABLE, **kwargs)
    assert not d.allowed
    assert resolver.calls == []


@pytest.mark.parametrize("target", ["a b", "http://[::1", "", "x" * 3000])
def test_zero_lookups_for_unparseable(target: str) -> None:
    d, resolver = run_decide(target, allow=(H,), table=TABLE)
    assert not d.allowed and resolver.calls == []


def test_exactly_one_lookup_for_an_authorised_name() -> None:
    d, resolver = run_decide(H, allow=(H,), table=TABLE)
    assert d.allowed and resolver.calls == [H]


def test_one_lookup_even_when_denied_after_resolution() -> None:
    d, resolver = run_decide(H, allow=(H,), table={H: ("169.254.169.254",)})
    assert not d.allowed and resolver.calls == [H]


@pytest.mark.parametrize("literal", ["192.0.2.1", "10.0.0.1", "169.254.169.254", "::1", "0x7f.1"])
def test_zero_lookups_for_ip_literals(literal: str) -> None:
    _, resolver = run_decide(literal, allow=("0.0.0.0/0", "::/0"))
    assert resolver.calls == []


def test_lookup_uses_canonical_host_not_raw_text() -> None:
    d, resolver = run_decide("HTTP://A.Lab.Test.:8080/x?y", allow=(H,), table=TABLE)
    assert d.allowed and resolver.calls == [H]
