"""Hypothesis properties of the strict canonical path and of string sanitizing."""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta, timezone

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from vulnscope.ledger import canonical as c
from vulnscope.ledger.errors import CanonicalizationError

SETTINGS = settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])

text = st.text(
    alphabet=st.characters(blacklist_categories=("Cs",)), max_size=30
)
json_values = st.recursive(
    st.one_of(st.none(), st.booleans(), st.integers(-(2**53 - 1), 2**53 - 1), text),
    lambda inner: st.one_of(st.lists(inner, max_size=4), st.dictionaries(text, inner, max_size=4)),
    max_leaves=25,
)


@SETTINGS
@given(value=json_values)
def test_canonical_is_idempotent_and_round_trips(value: object) -> None:
    once = c.canonical_json(value)
    assert c.canonical_json(json.loads(once)) == once
    assert json.loads(once) == value


@SETTINGS
@given(items=st.lists(st.tuples(text, st.integers(0, 99)), max_size=8, unique_by=lambda t: t[0]),
       seed=st.integers(0, 1000))
def test_key_insertion_order_is_irrelevant(items: list[tuple[str, int]], seed: int) -> None:
    import random

    shuffled = list(items)
    random.Random(seed).shuffle(shuffled)
    assert c.canonical_json(dict(items)) == c.canonical_json(dict(shuffled))


@SETTINGS
@given(f=st.floats(allow_nan=True, allow_infinity=True))
def test_floats_are_always_rejected(f: float) -> None:
    for wrapper in ({"a": f}, [f], f):
        try:
            c.canonical_json(wrapper)
        except CanonicalizationError:
            continue
        raise AssertionError("float accepted")


@SETTINGS
@given(n=st.integers(2**53, 2**80))
def test_ints_beyond_the_float_safe_range_are_rejected(n: int) -> None:
    for v in (n, -n):
        try:
            c.canonical_json({"a": v})
        except CanonicalizationError:
            continue
        raise AssertionError("out-of-range int accepted")


@SETTINGS
@given(cps=st.lists(st.integers(0xD800, 0xDFFF), min_size=1, max_size=3))
def test_lone_surrogates_are_always_rejected(cps: list[int]) -> None:
    s = "".join(map(chr, cps))
    for v in ({"a": s}, {s: 1}):
        try:
            c.canonical_json(v)
        except CanonicalizationError:
            continue
        raise AssertionError("lone surrogate accepted")


@SETTINGS
@given(
    ts=st.datetimes(min_value=datetime(2, 1, 1), max_value=datetime(9998, 1, 1)),
    offset_min=st.integers(-14 * 60, 14 * 60),
)
def test_ts_utc_normalisation_is_stable_and_round_trips(ts: datetime, offset_min: int) -> None:
    aware = ts.replace(tzinfo=timezone(timedelta(minutes=offset_min)))
    text_ = c.format_ts(aware)
    assert len(text_) == 27 and text_.endswith("Z")
    assert c.parse_ts(text_) == aware.astimezone(UTC)
    assert c.format_ts(c.parse_ts(text_)) == text_


@SETTINGS
@given(s=st.text(max_size=4_000))
def test_clean_str_is_idempotent_bounded_and_ascii_escaped(s: str) -> None:
    once, _ = c._clean_str(s)
    twice, reason = c._clean_str(once)
    assert twice == once and reason is None
    assert len(once) <= c.STR_CAP
    assert not any(ord(ch) < 32 or ord(ch) == 127 for ch in once)
    once.encode("utf-8")  # never a lone surrogate


@SETTINGS
@given(s=st.lists(st.integers(0, 0x10FFFF), max_size=4_000).map(lambda cps: "".join(map(chr, cps))))
def test_clean_str_is_total_on_arbitrary_code_points(s: str) -> None:
    once, _ = c._clean_str(s)
    assert c._clean_str(once) == (once, None)
    once.encode("utf-8")
