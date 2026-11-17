"""SQLAlchemy models backing the ledger: ``LedgerEntryRow`` (append-only,
with the ``UNIQUE(chain_id, seq)`` constraint that fixes pre-gate finding
SEC-5), ``ChainHeadRow`` (the lock target for D1's per-chain
serialization, resolving the ``SELECT ... FOR UPDATE``-requires-``UPDATE``
privilege contradiction -- see docs/gates/slice0-plan.md Section 3.10),
and ``CheckpointRow`` (signed anchors, D1).

This module is impure by design (it imports ``sqlalchemy``) -- it is the
deliberate bridge between the pure ``ledger.types.LedgerEntry``/
``Checkpoint`` dataclasses and the DB layer, used only by
``ledger/postgres_backend.py`` (Task B), never by ``ledger/types.py`` or
``ledger/chain.py`` themselves.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import JSON, DateTime, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from vulnscope.models.base import Base


class LedgerEntryRow(Base):
    __tablename__ = "ledger_entries"
    __table_args__ = (
        UniqueConstraint("chain_id", "seq", name="uq_ledger_entries_chain_id_seq"),
    )

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    chain_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    kind: Mapped[str] = mapped_column(String(64), nullable=False)
    actor: Mapped[str] = mapped_column(String(255), nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    record_hash: Mapped[str] = mapped_column(String(64), nullable=False)


class ChainHeadRow(Base):
    """One row per chain: the current ``seq``/``head_hash`` pointer.
    ``vulnscope_app`` is granted ``SELECT, INSERT, UPDATE`` here (never
    ``DELETE``/``TRUNCATE``) so ``append()`` can take ``SELECT ... FOR
    UPDATE`` on this table without needing ``UPDATE`` on
    ``ledger_entries`` itself (infra/postgres/init-roles.sql).
    """

    __tablename__ = "chain_heads"

    chain_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    seq: Mapped[int] = mapped_column(Integer, nullable=False, default=-1)
    head_hash: Mapped[str] = mapped_column(String(64), nullable=False)


class CheckpointRow(Base):
    __tablename__ = "checkpoints"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    chain_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    head_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    signature: Mapped[str] = mapped_column(String(256), nullable=False)
