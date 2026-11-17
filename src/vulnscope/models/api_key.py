"""``ApiKey`` model. Field shape pinned by docs/gates/slice0-plan.md
Section 3.7 (fixes STR-1): ``ApiKey(id, org_id, hashed_key, role, ...)``,
plus nullable/defaulted ``revoked_at`` (an explicit, deliberate addition
the plan calls out as not breaking keyword-argument construction).
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from vulnscope.models.base import Base, OrgScopedMixin, TimestampMixin


class ApiKey(Base, TimestampMixin, OrgScopedMixin):
    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    org_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("orgs.id"), nullable=False, index=True
    )
    hashed_key: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    role: Mapped[str] = mapped_column(String(16), nullable=False)  # admin|assessor|viewer
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
