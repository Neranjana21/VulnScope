"""Shared, pure ledger dataclasses (docs/gates/slice0-plan.md Section 3.2).

Built in Task 0 (moved here from Task B to fix pre-gate finding SEC-4) so
that ``policy/decide_and_record.py`` (Task A) and every ``ChainBackend``
implementation (Task B) code against the exact same frozen shapes without
either task blocking on the other. This module imports nothing from
``sqlalchemy``, ``fastapi``, ``models``, or ``api`` -- it is pure
dataclasses/typing, enforced by ``tests/unit/test_module_boundaries.py``.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Literal


@dataclass(frozen=True)
class LedgerEntry:
    """One row of a hash chain, matching docs/io-contracts.md's "Ledger
    entry" shape exactly."""

    schema_version: int
    chain_id: str  # "engagement:<id>" | "intake:<org_id>"
    seq: int
    kind: str  # "policy.decision" | "evidence" | "finding.transition" | "engagement.*" | "scan.*" | "checkpoint"
    actor: str  # "user:<id>" | "system"
    payload: Mapping[str, object]
    ts: datetime
    prev_hash: str
    record_hash: str


@dataclass(frozen=True)
class Checkpoint:
    """A signed anchor point: ``{chain_id, seq, head_hash, ts,
    signature}`` per docs/io-contracts.md."""

    chain_id: str
    seq: int
    head_hash: str
    ts: datetime
    signature: str  # hex-encoded Ed25519 signature


@dataclass(frozen=True)
class VerifyResult:
    """Result of ``ledger.verify.verify()`` (Task B); the four outcomes
    docs/decisions.md D1 names."""

    result: Literal["ok", "bad_record", "fork", "truncated"]
    first_bad_seq: int | None
    records: int
    checkpoint_seq: int | None
