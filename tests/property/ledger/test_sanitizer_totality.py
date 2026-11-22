# ruff: noqa: E501
"""Hypothesis totality of ``sanitize_payload`` and of ``append`` on both backend paths (rule 8)."""
from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from vulnscope.ledger import canonical as c
from vulnscope.ledger.memory_backend import InMemoryChainBackend
from vulnscope.ledger.verify import verify

CANARY = "CANARY-PROP-" + "f" * 24
TS = datetime(2026, 11, 19, tzinfo=UTC)
CHAIN = "intake:prop"


class Boom:
    def __str__(self) -> str:
        raise RuntimeError("called")

    __repr__ = __str__
    __hash__ = None  # type: ignore[assignment]

    def __eq__(self, other: object) -> bool:
        raise RuntimeError("called")


class BoomStr(str):
    def __str__(self) -> str:
        raise RuntimeError("called")


cps_text = st.lists(st.integers(0, 0x10FFFF), max_size=30).map(lambda cps: "".join(map(chr, cps)))
leaf = st.one_of(
    st.none(), st.booleans(), st.integers(-(2**70), 2**70), st.floats(), cps_text,
    st.binary(max_size=6), st.datetimes(), st.just(object()), st.builds(Boom),
    cps_text.map(BoomStr),
)
key = st.one_of(cps_text, st.integers(), st.binary(max_size=3), st.none())
tree = st.recursive(
    leaf,
    lambda inner: st.one_of(
        st.lists(inner, max_size=5), st.tuples(inner, inner), st.dictionaries(key, inner, max_size=5)
    ),
    max_leaves=40,
)
blocked_key = st.sampled_from(sorted(c.BLOCKED_KEYS)).flatmap(
    lambda k: st.sampled_from([k, k.upper(), k.title()])
)

SETTINGS = settings(max_examples=250, deadline=None,
                    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large])


@SETTINGS
@given(t=tree, bk=blocked_key, nest=st.booleans())
def test_sanitize_is_total_strict_valid_bounded_idempotent_and_never_leaks(
    t: object, bk: str, nest: bool
) -> None:
    secret = {bk: CANARY}
    payload = {"t": t, "n": [secret] if nest else secret}
    out = c.sanitize_payload(payload)
    n = len(c.canonical_json(c.normalize_payload(out)))
    assert n <= c.OUTPUT_BUDGET + c.RECORDS_RESERVE
    assert c.sanitize_payload(out) is out
    assert CANARY not in json.dumps(out)


@SETTINGS
@given(t=tree)
def test_append_never_raises_and_verifies_ok(t: object) -> None:
    async def go() -> tuple[str, int]:
        b = InMemoryChainBackend()
        await b.append(CHAIN, "policy.decision", "system", {"t": t}, TS)
        await b.append(CHAIN, "policy.decision", "system", c.sanitize_payload({"t": t}), TS)
        r = await verify(CHAIN, b)
        return r.result, r.records

    assert asyncio.run(go()) == ("ok", 2)


@SETTINGS
@given(payload=st.dictionaries(cps_text, st.one_of(st.none(), st.booleans(), st.integers(), cps_text),
                               max_size=6))
def test_a_flat_payload_survives_append_read_round_trip_equal_to_its_sanitized_form(
    payload: dict[str, object],
) -> None:
    async def go() -> object:
        b = InMemoryChainBackend()
        e = await b.append(CHAIN, "policy.decision", "system", payload, TS)
        (r,) = [x async for x in b.read(CHAIN)]
        assert dict(r.payload) == dict(e.payload)
        return dict(e.payload)

    stored = asyncio.run(go())
    assert stored == c.prepare_payload(payload)
