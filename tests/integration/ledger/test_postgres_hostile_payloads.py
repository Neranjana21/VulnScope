# ruff: noqa: E501
"""Hostile strings through the real ``json`` column: NUL, U+2028, emoji, bidi controls, 60 KB values
round-trip equal to the sanitized form and verify; secrets are redacted before storage (admin read)."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from ledger_pg_support import admin_fetch

from vulnscope.ledger.canonical import prepare_payload
from vulnscope.ledger.postgres_backend import PostgresChainBackend
from vulnscope.ledger.verify import verify

pytestmark = pytest.mark.integration
CANARY = "CANARY-PGH-" + uuid.uuid4().hex

CASES = {
    "nul": {"t": "a\x00b"},
    "controls": {"t": "x\x01\x1f\x7fy"},
    "u2028_bidi_emoji": {"t": " ‮⁦\U0001F600"},
    "lone_surrogate": {"t": "\ud800host.lab.test"},
    "60kb_value": {"t": "A" * 60_000},
    "floats_and_bytes": {"f": 1.5, "b": b"x", "n": float("nan")},
    "non_str_keys": {1: "a", None: "b"},
    "blocklisted_keys": {"Authorization": "Bearer " + CANARY, "nested": {"cookie": CANARY}},
    "backslashes_quotes": {"t": 'a\\b"c\\u0000'},
}


@pytest.mark.parametrize("name", sorted(CASES))
async def test_round_trip_equals_the_sanitized_form_and_verifies(
    backend: PostgresChainBackend, ledger_db: Any, name: str
) -> None:
    cid = f"intake:{uuid.uuid4()}"
    payload = CASES[name]
    entry = await backend.append(cid, "policy.decision", "system", payload, datetime.now(UTC))
    (row,) = [e async for e in backend.read(cid)]
    assert dict(row.payload) == dict(entry.payload) == prepare_payload(payload)
    assert row == entry
    assert (await verify(cid, backend)).result == "ok"
    stored = admin_fetch(ledger_db, "SELECT payload::text AS p FROM ledger_entries WHERE chain_id = $1", cid)
    assert len(stored) == 1 and CANARY not in stored[0]["p"]


async def test_a_denied_hostile_target_is_always_recordable(backend: PostgresChainBackend) -> None:
    cid = f"intake:{uuid.uuid4()}"
    hostile = {"allowed": False, "rule_id": "OUT_OF_SCOPE", "target": "\ud800" + "Z" * 1_000_000}
    e = await backend.append(cid, "policy.decision", "system", hostile, datetime.now(UTC))
    assert e.payload["allowed"] is False and e.payload["rule_id"] == "OUT_OF_SCOPE"
    assert e.payload["sanitized"] is True
