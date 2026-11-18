"""``Org`` model. Field shape pinned by docs/gates/slice0-plan.md Section
3.7 (fixes STR-1): ``Org(id, name, ...)``.
"""
from __future__ import annotations

import uuid

from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column

from vulnscope.models.base import Base, TimestampMixin


class Org(Base, TimestampMixin):
    __tablename__ = "orgs"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
