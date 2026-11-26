"""Scan status vocabulary and the ONLY place a scan's status is written (N-04, ADR-0006 decision 9).

Allowed transitions (anything else is a programming error and raises ``ValueError``):
    pending -> queued       scan creation, after the ``scan.created`` ledger entry exists
    pending -> cancelled    scan.created append failed, or a revoke raced the creation
    queued -> running       a worker (Slice 1)
    queued -> cancelled     revoke
    running -> cancelled    revoke
``cancelled`` is terminal and never restarts; nothing transitions back to ``pending``.
"""
from __future__ import annotations

from collections.abc import Iterable

from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from vulnscope.models.scan import Scan

SCAN_STATUSES: tuple[str, ...] = ("pending", "queued", "running", "cancelled")

ALLOWED_TRANSITIONS: frozenset[tuple[str, str]] = frozenset({
    ("pending", "queued"),
    ("pending", "cancelled"),
    ("queued", "running"),
    ("queued", "cancelled"),
    ("running", "cancelled"),
})


def is_allowed_transition(frm: str, to: str) -> bool:
    return (frm, to) in ALLOWED_TRANSITIONS


def assert_transition(frm: str, to: str) -> None:
    if not is_allowed_transition(frm, to):
        raise ValueError("scan status transition not allowed")


async def transition_scans(
    session: AsyncSession,
    *,
    org_id: str,
    to: str,
    frm: Iterable[str],
    scan_id: str | None = None,
    engagement_id: str | None = None,
) -> list[str]:
    """Move scans (selected by id or by engagement, always scoped by org) from any of ``frm`` to
    ``to``. Returns the ids moved. Every (from, to) pair is checked against the allowed list."""
    sources = tuple(frm)
    for s in sources:
        assert_transition(s, to)
    if (scan_id is None) == (engagement_id is None):
        raise ValueError("select by exactly one of scan_id or engagement_id")
    stmt = update(Scan).where(Scan.org_id == org_id, Scan.status.in_(sources))
    stmt = stmt.where(Scan.id == scan_id) if scan_id is not None \
        else stmt.where(Scan.engagement_id == engagement_id)
    res = await session.execute(stmt.values(status=to).returning(Scan.id))
    return [r[0] for r in res.all()]
