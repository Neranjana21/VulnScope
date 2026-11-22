"""SEC-A10: lab_cidr validation; invalid lab config denies when lab is enabled."""

from __future__ import annotations

import pytest
from policy_test_support import run_decide

from vulnscope.policy.private_ranges import parse_lab_cidr
from vulnscope.policy.types import RuleId

BAD = [
    "0.0.0.0/0",
    "8.8.8.0/24",
    "169.254.0.0/16",
    "garbage",
    "",
    " ",
    "10.0.0.0/7",
    "10.0.0.1/8",
    "::/0",
    "2001:db8::/32",
    "fc00::/7x",
    "fd00::/47",
    "10.0.0.0/8\n",
    "192.0.2.0/24",
    "::ffff:10.0.0.0/104",
]


@pytest.mark.parametrize("text", BAD)
def test_parse_rejects(text: str) -> None:
    with pytest.raises(ValueError):
        parse_lab_cidr(text)


def test_non_string_is_type_error() -> None:
    with pytest.raises(TypeError):
        parse_lab_cidr(5)  # type: ignore[arg-type]


@pytest.mark.parametrize("text", BAD)
def test_invalid_lab_config_denies_with_lab_enabled(text: str) -> None:
    for profile in ("lab", "standard"):
        d, resolver = run_decide(
            "127.0.0.1",
            allow=("127.0.0.1", "0.0.0.0/0"),
            profile=profile,
            lab_enabled=True,
            lab_cidr=text,
        )
        assert d.rule_id == RuleId.OUT_OF_SCOPE
        assert d.reason == "invalid lab configuration"
        assert not d.allowed
        assert resolver.calls == []


@pytest.mark.parametrize("text", BAD)
def test_lab_cidr_ignored_when_lab_disabled(text: str) -> None:
    d, _ = run_decide("192.0.2.1", allow=("192.0.2.1",), lab_enabled=False, lab_cidr=text)
    assert d.allowed


def test_non_string_lab_cidr_is_a_programming_error() -> None:
    with pytest.raises(TypeError):
        run_decide("192.0.2.1", allow=("192.0.2.1",), lab_enabled=True, lab_cidr=5)  # type: ignore[arg-type]
