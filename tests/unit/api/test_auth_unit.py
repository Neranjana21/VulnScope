"""api/auth.py pure helpers (design 3, PD-20)."""
from __future__ import annotations

import hashlib
import re

from hypothesis import given
from hypothesis import strategies as st

from vulnscope.api.auth import Role, hash_api_key, parse_bearer

TOKEN = "vs_test_" + "a" * 32  # 40 chars


def test_hash_is_sha256_hex_and_deterministic() -> None:
    h = hash_api_key(TOKEN)
    assert h == hashlib.sha256(TOKEN.encode()).hexdigest()
    assert re.fullmatch(r"[0-9a-f]{64}", h)
    assert hash_api_key(TOKEN) == h
    assert hash_api_key(TOKEN + "x") != h


def test_parse_bearer_accepts_scheme_case_insensitively() -> None:
    for scheme in ("Bearer", "bearer", "BEARER", "bEaReR"):
        assert parse_bearer(f"{scheme} {TOKEN}") == TOKEN


def test_parse_bearer_min_length_boundary() -> None:
    assert parse_bearer("Bearer " + "a" * 31) is None
    assert parse_bearer("Bearer " + "a" * 32) == "a" * 32
    assert parse_bearer("Bearer " + "a" * 256) == "a" * 256
    assert parse_bearer("Bearer " + "a" * 257) is None


def test_parse_bearer_rejects_malformed() -> None:
    bad = [None, "", "Bearer", "Bearer ", f"Basic {TOKEN}", TOKEN, f"Bearer {TOKEN} {TOKEN}",
           f"Bearer  {TOKEN}", f"Bearer {TOKEN}\n", "Bearer " + "a" * 31 + "\x00",
           "Bearer " + "é" * 40, "Bearer " + "a" * 20 + " " + "b" * 20]
    for header in bad:
        assert parse_bearer(header) is None


@given(st.one_of(st.none(), st.text(max_size=400)))
def test_parse_bearer_never_raises_and_is_printable(header: str | None) -> None:
    out = parse_bearer(header)
    if out is not None:
        assert 32 <= len(out) <= 256
        assert all(0x21 <= ord(c) <= 0x7E for c in out)


def test_role_values() -> None:
    assert {r.value for r in Role} == {"admin", "assessor", "viewer"}
