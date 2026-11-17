"""SQLAlchemy declarative base and shared mixins
(docs/gates/slice0-plan.md Section 2).
"""
from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import DateTime, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Shared declarative base. ``alembic/env.py`` imports
    ``Base.metadata`` as ``target_metadata``; importing
    ``vulnscope.models.base`` always runs ``vulnscope/models/__init__.py``
    first (ordinary Python package-import semantics), which is what
    registers every table defined in this package onto this metadata
    object before anything reads it.
    """


def utcnow() -> datetime:
    return datetime.now(UTC)


class TimestampMixin:
    """``created_at``/``updated_at``, tz-aware UTC."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )


class OrgScopedMixin:
    """Every table carries ``org_id`` (CLAUDE.md stack conventions)."""

    org_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)


class EngagementScopedMixin:
    """Engagement-scoped rows additionally carry ``engagement_id``."""

    engagement_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
