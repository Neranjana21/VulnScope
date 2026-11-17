"""Ledger entry / verify / checkpoint view schemas, matching
docs/io-contracts.md "Ledger entry" exactly."""
from __future__ import annotations

from typing import Any, Literal

from vulnscope.models.schemas.common import SchemaVersion1, StrictModel, UtcDateTime


class LedgerEntryView(StrictModel):
    schema_version: SchemaVersion1
    chain_id: str
    seq: int
    kind: str
    actor: str
    payload: dict[str, Any]
    ts: UtcDateTime
    prev_hash: str
    record_hash: str


class VerifyResponse(StrictModel):
    result: Literal["ok", "bad_record", "fork", "truncated"]
    first_bad_seq: int | None
    records: int
    checkpoint_seq: int | None


class CheckpointView(StrictModel):
    chain_id: str
    seq: int
    head_hash: str
    ts: UtcDateTime
    signature: str
