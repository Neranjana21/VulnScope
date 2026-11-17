"""``User`` model. Minimal S0 shape: io-contracts.md does not define a
dedicated User request/response object (auth is API-key based, D11), but
ledger entries reference ``actor: "user:<id>"``, so a row needs to exist
to back that id.
"""
from __future__ import annotations

import uuid

from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column

from vulnscope.models.base import Base, OrgScopedMixin, TimestampMixin


class User(Base, TimestampMixin, OrgScopedMixin):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    email: Mapped[str] = mapped_column(String(320), nullable=False, unique=True)
    role: Mapped[str] = mapped_column(String(16), nullable=False)  # admin|assessor|viewer
