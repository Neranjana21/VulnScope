"""DE-01: the revoke memo row lives in a key space a client cannot produce, and client
Idempotency-Keys that use the reserved forms are rejected before anything is written."""
from __future__ import annotations

import re

import pytest
from hypothesis import given
from hypothesis import strategies as st

from vulnscope.api.idempotency import (
    RESERVED_KEY_PREFIXES,
    parse_key_header,
    storage_key,
    storage_preimage,
)
from vulnscope.api.problem import ProblemError
from vulnscope.api.revoke_recorder import memo_key, memo_preimage

EID = "e" * 32


def test_memo_key_is_not_the_storage_key_of_any_reserved_client_key() -> None:
    for raw in (f"revoke-record:{EID}", f"revoke-memo-v1:{EID}", f"revoke-memo-v1:3:org:{EID}"):
        assert memo_key("org", EID) != storage_key("org", raw)
    assert re.fullmatch(r"[0-9a-f]{64}", memo_key("org", EID))


def test_preimages_live_in_disjoint_namespaces() -> None:
    assert memo_preimage("org", EID).startswith("revoke-memo-v1:")
    assert storage_preimage("org", "anything").startswith("idem-v1:")
    assert not memo_preimage("org", EID).startswith("idem-v1:")


@given(st.text(min_size=1, max_size=30), st.text(max_size=60))
def test_no_client_key_reaches_the_memo_preimage_namespace(org: str, raw: str) -> None:
    """The client preimage always starts with the fixed ``idem-v1:`` marker, the memo preimage
    never does, so (SHA-256) the two key spaces cannot meet."""
    assert storage_preimage(org, raw).startswith("idem-v1:")
    assert not memo_preimage(org, raw).startswith("idem-v1:")


@given(st.tuples(st.text(max_size=12), st.text(max_size=12)),
       st.tuples(st.text(max_size=12), st.text(max_size=12)))
def test_memo_key_is_injective(p: tuple[str, str], q: tuple[str, str]) -> None:
    if p != q:
        assert memo_key(*p) != memo_key(*q)


def test_memo_key_length_prefix_on_the_ambiguous_pairs() -> None:
    assert memo_key("a", "b:c") != memo_key("a:b", "c")
    assert memo_key("ab", "c") != memo_key("a", "bc")


@pytest.mark.parametrize("raw", [
    f"revoke-record:{EID}", "revoke-record:", f"REVOKE-RECORD:{EID}", f"Revoke-Record:{EID}",
    f"revoke-memo-v1:{EID}", "revoke-memo-v1:", "revoke-memo-v2:x", f"REVOKE-MEMO-V1:{EID}",
])
def test_reserved_client_keys_are_rejected(raw: str) -> None:
    with pytest.raises(ProblemError) as ei:
        parse_key_header([raw])
    assert ei.value.status == 422 and ei.value.code.value == "INVALID_REQUEST"


@pytest.mark.parametrize("raw", ["revoke", "revoke-x", "revokes-record:1", "my-revoke-record:1",
                                 "xrevoke-memo-v1:1", "idem-v1:1", "record:revoke"])
def test_near_miss_client_keys_are_still_accepted(raw: str) -> None:
    assert parse_key_header([raw]) == raw


def test_reserved_prefix_table_is_lowercase_and_pinned() -> None:
    assert RESERVED_KEY_PREFIXES == ("revoke-record:", "revoke-memo-")
