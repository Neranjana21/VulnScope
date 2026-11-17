"""``Engagement`` model -- holds authorization, scope, window, identities,
ownership rules and asset tags (D13). Structured sub-objects are stored as
JSON; the request/response shape is validated at the API boundary by
``models/schemas/engagement.py``, not re-validated here.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import JSON, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from vulnscope.models.base import Base, OrgScopedMixin, TimestampMixin


class Engagement(Base, TimestampMixin, OrgScopedMixin):
    __tablename__ = "engagements"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    profile: Mapped[str] = mapped_column(String(16), nullable=False)  # standard|lab
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="active")  # active|revoked

    targets: Mapped[dict] = mapped_column(JSON, nullable=False)
    scope: Mapped[dict] = mapped_column(JSON, nullable=False)
    authorization: Mapped[dict] = mapped_column(JSON, nullable=False)
    identities: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    ownership_rules: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    asset_tags: Mapped[list] = mapped_column(JSON, nullable=False, default=list)

    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
    revoked_reason: Mapped[str | None] = mapped_column(String(1024), nullable=True, default=None)
