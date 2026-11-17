"""``Evidence`` model, matching docs/io-contracts.md's "Evidence record"
object. Excerpts are size-capped (``String(4096)``) and expected to be
redacted at ingest (CLAUDE.md rule 6); this model stores whatever the
caller already redacted, it does not redact itself.
"""
from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import JSON, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from vulnscope.models.base import Base, EngagementScopedMixin, OrgScopedMixin, TimestampMixin


class Evidence(Base, TimestampMixin, OrgScopedMixin, EngagementScopedMixin):
    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    engagement_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("engagements.id"), nullable=False, index=True
    )
    finding_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("findings.id"), nullable=False, index=True
    )
    kind: Mapped[str] = mapped_column(String(64), nullable=False)
    redacted_excerpt: Mapped[str] = mapped_column(String(4096), nullable=False)
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    identity_label: Mapped[str | None] = mapped_column(String(128), nullable=True)
    expected: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    observed: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    policy_version: Mapped[str] = mapped_column(String(128), nullable=False)
    adapter: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    ledger_chain: Mapped[str] = mapped_column(String(255), nullable=False)
    ledger_seq: Mapped[int] = mapped_column(Integer, nullable=False)
