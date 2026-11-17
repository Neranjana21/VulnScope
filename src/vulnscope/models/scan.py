"""``Scan`` model -- one run under an engagement (D13)."""
from __future__ import annotations

import uuid

from sqlalchemy import JSON, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from vulnscope.models.base import Base, EngagementScopedMixin, OrgScopedMixin, TimestampMixin


class Scan(Base, TimestampMixin, OrgScopedMixin, EngagementScopedMixin):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    engagement_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("engagements.id"), nullable=False, index=True
    )
    stages: Mapped[list] = mapped_column(JSON, nullable=False)
    options: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    schedule: Mapped[dict | None] = mapped_column(JSON, nullable=True, default=None)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="queued")
