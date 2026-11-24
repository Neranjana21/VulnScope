"""api/idempotency.py pure helpers (design 5, PD-11)."""
from __future__ import annotations

import re

import pytest
from hypothesis import given
from hypothesis import strategies as st

from vulnscope.api.idempotency import parse_key_header, request_hash, storage_key
from vulnscope.api.problem import ProblemError


def test_storage_key_shape_and_org_separation() -> None:
    k = storage_key("org-1", "key")
    assert re.fullmatch(r"[0-9a-f]{64}", k)
    assert k != storage_key("org-2", "key")
    assert "key" not in k


def test_storage_key_length_prefix_is_injective_on_the_ambiguous_pairs() -> None:
    assert storage_key("a", "b:c") != storage_key("a:b", "c")
    assert storage_key("a", ":b") != storage_key("a:", "b")
    assert storage_key("ab", "c") != storage_key("a", "bc")


@given(st.tuples(st.text(max_size=20), st.text(max_size=20)),
       st.tuples(st.text(max_size=20), st.text(max_size=20)))
def test_storage_key_never_collides(p: tuple[str, str], q: tuple[str, str]) -> None:
    if p != q:
        assert storage_key(*p) != storage_key(*q)


def test_request_hash_ignores_key_order_and_whitespace_but_not_values() -> None:
    a = request_hash("POST", "/v1/engagements", {"a": 1, "b": [1, 2, {"c": "x"}]})
    b = request_hash("POST", "/v1/engagements", {"b": [1, 2, {"c": "x"}], "a": 1})
    assert a == b and re.fullmatch(r"[0-9a-f]{64}", a)
    assert a != request_hash("POST", "/v1/engagements", {"a": 1, "b": [1, 2, {"c": "y"}]})
    assert a != request_hash("PUT", "/v1/engagements", {"a": 1, "b": [1, 2, {"c": "x"}]})
    assert a != request_hash("POST", "/v1/other", {"a": 1, "b": [1, 2, {"c": "x"}]})
    assert request_hash("POST", "/p", 5) != request_hash("POST", "/p", 5.0)


def test_parse_key_header_accepts_and_absent() -> None:
    assert parse_key_header([]) is None
    assert parse_key_header(["k" * 255]) == "k" * 255
    assert parse_key_header(["abc-123_~!"]) == "abc-123_~!"


@pytest.mark.parametrize(
    "values",
    [["k" * 256], [""], ["a b"], ["a\x00b"], ["a\r\nb"], ["é"], ["one", "two"], ["a\tb"]],
)
def test_parse_key_header_rejects(values: list[str]) -> None:
    with pytest.raises(ProblemError) as ei:
        parse_key_header(values)
    assert ei.value.status == 422 and ei.value.code.value == "INVALID_REQUEST"
