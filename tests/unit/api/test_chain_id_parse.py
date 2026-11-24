"""api/scoping.py parse_chain_id (design 4)."""
from __future__ import annotations

import re

import pytest
from hypothesis import given
from hypothesis import strategies as st

from vulnscope.api.scoping import parse_chain_id

SHAPE = re.compile(r"(engagement|intake):([0-9a-f-]{1,64})")


def test_accepts_exactly_the_two_shapes() -> None:
    assert parse_chain_id("engagement:0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b") == (
        "engagement", "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b")
    assert parse_chain_id("intake:abc-1") == ("intake", "abc-1")


@pytest.mark.parametrize(
    "bad",
    ["", "engagement:", "intake:", "engagement:ABC", "engagement:abc\n", "evidence:abc",
     "engagement:../x", "engagement:" + "a" * 65, "engagement:a b", "engagement:abc:def",
     " engagement:abc", "ENGAGEMENT:abc", "engagement:é", "engagement:a\x00"],
)
def test_rejects_everything_else(bad: str) -> None:
    assert parse_chain_id(bad) is None


@given(st.text(max_size=120))
def test_never_raises_and_matches_only_the_shape(s: str) -> None:
    out = parse_chain_id(s)
    m = SHAPE.fullmatch(s)
    assert (out is None) == (m is None)
    if m:
        assert out == (m.group(1), m.group(2))
