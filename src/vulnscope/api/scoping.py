"""Org scoping and engagement/scan persistence: the ONLY module routers use to read or write
``Engagement`` and ``Scan`` rows (T9). Every lookup includes the caller's ``org_id``; a miss and a
foreign row are the same 404 and write nothing.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal, NoReturn

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from vulnscope.api.ports import EngagementSnapshot
from vulnscope.api.problem import Detail, ProblemError
from vulnscope.errors import ReasonCode
from vulnscope.models.engagement import Engagement
from vulnscope.models.org import Org
from vulnscope.models.scan import Scan
from vulnscope.models.schemas.engagement import EngagementCreateRequest

_PATH_ID = re.compile(r"[\x21-\x7e]{1,64}")
_CHAIN_RE = re.compile(r"(engagement|intake):([0-9a-f-]{1,64})")


def not_found() -> NoReturn:
    raise ProblemError(404, ReasonCode.NOT_FOUND, Detail.NOT_FOUND)


def valid_path_id(value: str) -> bool:
    return bool(_PATH_ID.fullmatch(value))


def snapshot_of(e: Engagement) -> EngagementSnapshot:
    return EngagementSnapshot(
        id=e.id, org_id=e.org_id, name=e.name, profile=e.profile, status=e.status,
        targets=dict(e.targets), scope=dict(e.scope), authorization=dict(e.authorization),
        identities=list(e.identities), ownership_rules=list(e.ownership_rules),
        asset_tags=list(e.asset_tags), created_at=e.created_at, revoked_at=e.revoked_at,
        revoked_reason=e.revoked_reason)


async def get_engagement(session: AsyncSession, engagement_id: str, org_id: str
                         ) -> EngagementSnapshot:
    if not valid_path_id(engagement_id):
        not_found()
    row = (await session.execute(select(Engagement).where(
        Engagement.id == engagement_id, Engagement.org_id == org_id))).scalar_one_or_none()
    if row is None:
        not_found()
    return snapshot_of(row)


@dataclass(frozen=True)
class ScanRecord:
    id: str
    engagement_id: str
    org_id: str
    status: str
    stages: list[str]
    options: dict[str, Any]
    schedule: dict[str, Any] | None


async def get_scan(session: AsyncSession, scan_id: str, org_id: str) -> ScanRecord:
    """Both tables are constrained by the caller's org, so a corrupted row in either cannot leak."""
    if not valid_path_id(scan_id):
        not_found()
    row = (await session.execute(
        select(Scan).join(Engagement, Scan.engagement_id == Engagement.id)
        .where(Scan.id == scan_id, Scan.org_id == org_id, Engagement.org_id == org_id)
    )).scalar_one_or_none()
    if row is None:
        not_found()
    return ScanRecord(row.id, row.engagement_id, row.org_id, row.status, list(row.stages),
                      dict(row.options), row.schedule)


async def lock_engagement_status(session: AsyncSession, engagement_id: str, org_id: str) -> str:
    """``SELECT ... FOR UPDATE``: serialises scan creation against revoke. Returns the status."""
    status = (await session.execute(
        select(Engagement.status).where(Engagement.id == engagement_id,
                                        Engagement.org_id == org_id).with_for_update()
    )).scalar_one_or_none()
    if status is None:
        not_found()
    return str(status)


async def insert_engagement(session: AsyncSession, *, engagement_id: str, org_id: str,
                            req: EngagementCreateRequest, now: datetime) -> None:
    session.add(Engagement(
        id=engagement_id, org_id=org_id, name=req.name, profile=req.profile, status="active",
        targets=req.targets.model_dump(mode="json"), scope=req.scope.model_dump(mode="json"),
        authorization=req.authorization.model_dump(mode="json"),
        identities=[i.model_dump(mode="json") for i in req.identities],
        ownership_rules=[o.model_dump(mode="json") for o in req.ownership_rules],
        asset_tags=[a.model_dump(mode="json") for a in req.asset_tags],
        created_at=now, updated_at=now))
    await session.flush()


async def insert_scan(session: AsyncSession, *, scan_id: str, org_id: str, engagement_id: str,
                      stages: list[str], now: datetime) -> None:
    session.add(Scan(id=scan_id, org_id=org_id, engagement_id=engagement_id, stages=stages,
                     options={"write_tests": False}, schedule=None, status="pending",
                     created_at=now, updated_at=now))
    await session.flush()


async def revoke_effect(session: AsyncSession, *, engagement_id: str, org_id: str,
                        now: datetime, reason: str) -> bool:
    """Flip ``active -> revoked``. True when THIS call performed the effect."""
    res = await session.execute(
        update(Engagement)
        .where(Engagement.id == engagement_id, Engagement.org_id == org_id,
               Engagement.status == "active")
        .values(status="revoked", revoked_at=now, revoked_reason=reason, updated_at=now)
        .returning(Engagement.id))
    return res.first() is not None


def parse_chain_id(chain_id: str) -> tuple[Literal["engagement", "intake"], str] | None:
    m = _CHAIN_RE.fullmatch(chain_id)
    if m is None:
        return None
    kind = m.group(1)
    assert kind in ("engagement", "intake")
    return kind, m.group(2)  # type: ignore[return-value]


async def resolve_chain_owner_org(session: AsyncSession, chain_id: str) -> str | None:
    """The org that owns ``chain_id``, or None (unknown, malformed or hostile)."""
    parsed = parse_chain_id(chain_id)
    if parsed is None:
        return None
    kind, ident = parsed
    if kind == "engagement":
        return (await session.execute(select(Engagement.org_id).where(
            Engagement.id == ident))).scalar_one_or_none()
    return (await session.execute(select(Org.id).where(Org.id == ident))).scalar_one_or_none()
