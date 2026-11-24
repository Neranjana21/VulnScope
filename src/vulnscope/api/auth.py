"""API-key authentication (design 3, PD-20, ADR-0006 decision 2).

Keys are server-minted random tokens of at least 128 bits; the stored value is the unsalted
SHA-256 hex of the token (acceptable only for high-entropy tokens; it is not a password hash).
The raw key, its hash and the Authorization header are never logged or echoed.
"""
from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass
from enum import Enum

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vulnscope.models.api_key import ApiKey

MIN_TOKEN = 32
MAX_TOKEN = 256
_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")
_DUMMY_HASH = hashlib.sha256(b"vulnscope-dummy-key").hexdigest()


class Role(str, Enum):
    ADMIN = "admin"
    ASSESSOR = "assessor"
    VIEWER = "viewer"


@dataclass(frozen=True)
class Principal:
    api_key_id: str
    org_id: str
    role: Role | None  # None: the stored role value is not in the enum (fails closed to 403)

    @property
    def actor(self) -> str:
        return f"user:{self.api_key_id}"


def hash_api_key(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def parse_bearer(header: str | None) -> str | None:
    """Return the token, or None for anything that is not exactly ``Bearer <32..256 printable>``."""
    if header is None or len(header) > MAX_TOKEN + 16:
        return None
    scheme, sep, token = header.partition(" ")
    if not sep or scheme.lower() != "bearer":
        return None
    if not (MIN_TOKEN <= len(token) <= MAX_TOKEN):
        return None
    if any(not (0x21 <= ord(c) <= 0x7E) for c in token):
        return None
    return token


async def authenticate(session: AsyncSession, raw: str) -> Principal | None:
    digest = hash_api_key(raw)
    row = (await session.execute(
        select(ApiKey.id, ApiKey.org_id, ApiKey.role, ApiKey.hashed_key)
        .where(ApiKey.hashed_key == digest, ApiKey.revoked_at.is_(None)))).first()
    stored = row.hashed_key if row is not None else _DUMMY_HASH
    same = hmac.compare_digest(stored, digest)  # defence in depth; same work on both paths
    if row is None or not same:
        return None
    if not _ID_RE.fullmatch(row.id):  # becomes the ledger actor; fail closed
        return None
    try:
        role: Role | None = Role(row.role)
    except ValueError:
        role = None
    return Principal(api_key_id=row.id, org_id=row.org_id, role=role)
