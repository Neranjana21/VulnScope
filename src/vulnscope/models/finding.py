"""``Finding`` model, matching docs/io-contracts.md's "Finding" object."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from vulnscope.models.base import (
    Base,
    EngagementScopedMixin,
    OrgScopedMixin,
    TimestampMixin,
    utcnow,
)


class Finding(Base, TimestampMixin, OrgScopedMixin, EngagementScopedMixin):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    engagement_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("engagements.id"), nullable=False, index=True
    )
    asset_id: Mapped[str] = mapped_column(String(36), nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    cwe: Mapped[str | None] = mapped_column(String(32), nullable=True)
    taxonomy: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    owasp_api: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="candidate")
    severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    evidence_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    cvss: Mapped[dict] = mapped_column(JSON, nullable=False)
    priority: Mapped[dict] = mapped_column(JSON, nullable=False)
    source_adapter: Mapped[dict] = mapped_column(JSON, nullable=False)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
