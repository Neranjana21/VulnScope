"""``IdempotencyKeyRow`` -- backs the ``Idempotency-Key`` header semantics
(docs/io-contracts.md "Conventions": same key + same body returns the
original response; same key + different body returns 409; keys kept 24h).
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from vulnscope.models.base import Base, utcnow


class IdempotencyKeyRow(Base):
    __tablename__ = "idempotency_keys"

    key: Mapped[str] = mapped_column(String(255), primary_key=True)
    org_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    request_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    response_body: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    response_status: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
