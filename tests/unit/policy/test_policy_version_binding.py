"""compute_policy_version (pure, hashes the raw lab_cidr string; RC8)."""

from __future__ import annotations

import re

import pytest

from vulnscope.policy import denylist
from vulnscope.policy.denylist import RULESET_SEMVER, compute_policy_version


def v(**kw: object) -> str:
    return compute_policy_version(**kw)  # type: ignore[arg-type]


def test_format_and_determinism() -> None:
    a = v(lab_enabled=False, lab_cidr=None)
    assert re.fullmatch(rf"{re.escape(RULESET_SEMVER)}\+[0-9a-f]{{16}}", a)
    assert a == v(lab_enabled=False, lab_cidr=None)


def test_lab_flag_and_cidr_change_version() -> None:
    base = v(lab_enabled=False, lab_cidr=None)
    on = v(lab_enabled=True, lab_cidr=None)
    cidr = v(lab_enabled=True, lab_cidr="10.0.0.0/8")
    assert len({base, on, cidr}) == 3


def test_raw_string_sensitivity_without_parsing() -> None:
    assert v(lab_enabled=True, lab_cidr="10.0.0.0/8") != v(lab_enabled=True, lab_cidr="10.0.0.0/08")
    # garbage never raises
    v(lab_enabled=True, lab_cidr="garbage")
    v(lab_enabled=True, lab_cidr="")


def test_disabled_lab_ignores_the_cidr() -> None:
    base = v(lab_enabled=False, lab_cidr=None)
    assert v(lab_enabled=False, lab_cidr="garbage") == base
    assert v(lab_enabled=False, lab_cidr="10.0.0.0/8") == base


def test_non_string_cidr_is_a_type_error() -> None:
    with pytest.raises(TypeError):
        v(lab_enabled=True, lab_cidr=5)


def test_any_always_deny_entry_changes_the_version(monkeypatch: pytest.MonkeyPatch) -> None:
    import ipaddress

    base = v(lab_enabled=False, lab_cidr=None)
    monkeypatch.setattr(
        denylist,
        "ALWAYS_DENY_NETWORKS",
        (*denylist.ALWAYS_DENY_NETWORKS, ipaddress.ip_network("198.18.0.0/15")),
    )
    assert v(lab_enabled=False, lab_cidr=None) != base
    monkeypatch.undo()
    monkeypatch.setattr(denylist, "ALWAYS_DENY_EXACT_NAMES", frozenset({"metadata"}))
    assert v(lab_enabled=False, lab_cidr=None) != base
    monkeypatch.undo()
    monkeypatch.setattr(denylist, "ALWAYS_DENY_NAME_SUFFIXES", ("metadata.google.internal",))
    assert v(lab_enabled=False, lab_cidr=None) != base


def test_keyword_only() -> None:
    with pytest.raises(TypeError):
        compute_policy_version(False, None)  # type: ignore[misc]
