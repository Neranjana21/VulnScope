"""Revoke: effect first, record second (design 6, PD-06, PD-07, N-02, N-05; ADR-0006 decision 6).

The revoke effect (status flip and cancellation of live scans) commits in one short transaction.
Recording the ``engagement.revoked`` ledger entry is single-flight through a memo/claim row in
``idempotency_keys`` (no migration). Recording never depends on searching the chain: if the chain
is beyond the search cap, or the search times out or fails, the entry is appended anyway (a
duplicate is tolerated, the lowest seq is the one found later).
"""
from __future__ import annotations

import asyncio
import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select

from vulnscope.api import ledger_io
from vulnscope.api.auth import Principal
from vulnscope.api.db import db_read, db_tx
from vulnscope.api.idempotency import (
    claim_insert,
    delete_key,
    finalize,
    mark_stale,
    read_row,
    takeover,
)
from vulnscope.api.logging import log_event
from vulnscope.api.ports import EngagementSnapshot
from vulnscope.api.problem import Detail, ProblemError
from vulnscope.api.scan_status import transition_scans
from vulnscope.api.scoping import get_engagement, revoke_effect, snapshot_of
from vulnscope.api.state import AppState
from vulnscope.errors import ReasonCode
from vulnscope.models.engagement import Engagement

MEMO_HASH = hashlib.sha256(b"revoke-record").hexdigest()
TAIL = 256
LIVE_SCAN_STATUSES = ("pending", "queued", "running")


def memo_preimage(org_id: str, engagement_id: str) -> str:
    """A namespace disjoint from ``idempotency.storage_preimage`` (which always starts with
    ``idem-v1:``), so no client Idempotency-Key can address or occupy a memo row (DE-01)."""
    return f"revoke-memo-v1:{len(org_id)}:{org_id}:{engagement_id}"


def memo_key(org_id: str, engagement_id: str) -> str:
    return hashlib.sha256(memo_preimage(org_id, engagement_id).encode()).hexdigest()


@dataclass(frozen=True)
class Recorded:
    seq: int
    appended: bool


def _unavailable() -> ProblemError:
    return ProblemError(503, ReasonCode.UNAVAILABLE, Detail.UNAVAILABLE,
                        headers={"Retry-After": "1"})


async def _find_existing(state: AppState, snap: EngagementSnapshot) -> int | None:
    """Optimisation only: the lowest-seq ``engagement.revoked`` entry for this engagement."""
    t = state.timeouts
    chain = f"engagement:{snap.id}"
    try:
        async with asyncio.timeout(t.revoke_search_budget_s):
            head = await state.chain_backend.head(chain)
            n = head.seq + 1 if head is not None else 0
            start, limit = (0, None) if n <= t.max_chain_scan else (max(0, n - TAIL), TAIL)
            async for e in state.chain_backend.read(chain, start, limit):
                if e.kind == "engagement.revoked" and e.payload.get("engagement_id") == snap.id:
                    return int(e.seq)
    except Exception:  # noqa: BLE001 - timeout or read failure: append decides, never 503 here
        return None
    return None


async def _memo_is_valid(state: AppState, snap: EngagementSnapshot, seq: object) -> bool:
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
        return False
    try:
        async for e in state.chain_backend.read(f"engagement:{snap.id}", seq, 1):
            return bool(e.seq == seq and e.kind == "engagement.revoked"
                        and e.payload.get("engagement_id") == snap.id)
    except Exception:  # noqa: BLE001 - cannot confirm: fail closed to 503
        raise _unavailable() from None
    return False


async def _winner(state: AppState, snap: EngagementSnapshot, key: str, *, revoked_by: str,
                  actor: str, repaired: bool) -> Recorded:
    try:
        existing = await _find_existing(state, snap)
        if existing is not None:
            seq, appended = existing, False
        else:
            payload = ledger_io.engagement_revoked(
                state.sanitize, engagement_id=snap.id,
                revoked_at=snap.revoked_at or state.clock.now(),
                reason=snap.revoked_reason or "", revoked_by=revoked_by, repaired=repaired)
            entry = await ledger_io.append_entry(
                state, f"engagement:{snap.id}", "engagement.revoked", actor, payload)
            seq, appended = int(entry.seq), True
    except BaseException:
        try:  # keep the claim body (revoked_by); make it stale so the next caller takes over
            async with db_tx(state) as s:
                await mark_stale(s, key, state.clock.now() - timedelta(days=1))
        except Exception:  # noqa: BLE001
            pass
        raise
    try:
        async with db_tx(state) as s:
            await finalize(s, key, 200, {"seq": seq, "revoked_by": revoked_by})
    except Exception:  # noqa: BLE001 - the entry exists; the next call finds it by search
        pass
    return Recorded(seq, appended)


async def ensure_revoked_entry(state: AppState, snap: EngagementSnapshot, *, actor: str,
                               revoked_by: str | None = None,
                               owns_claim: bool = False) -> Recorded:
    """Return the seq of the ONE ``engagement.revoked`` entry, appending it if absent."""
    key = memo_key(snap.org_id, snap.id)
    t = state.timeouts
    if owns_claim:  # the effect transaction inserted the claim for this request
        return await _winner(state, snap, key, revoked_by=revoked_by or "unknown", actor=actor,
                             repaired=False)
    loop = asyncio.get_running_loop()
    t_end = loop.time() + t.claim_wait_s
    while True:
        memo_seq: object = None
        take: str | None = None
        async with db_tx(state) as s:
            now = state.clock.now()
            row = await read_row(s, key)
            if row is None:
                if await claim_insert(s, key=key, org_id=snap.org_id, rhash=MEMO_HASH, now=now,
                                      body={"revoked_by": "unknown"}):
                    take = "unknown"
            elif row.status == 200:
                memo_seq = row.body.get("seq")
            elif row.status != 0:  # not a claim and not a memo: foreign or corrupt, never waited on
                memo_seq = -1  # fails validation below: discard the row and record again
            else:
                cutoff = now - timedelta(seconds=t.revoke_claim_stale_s)
                if row.created_at < cutoff and await takeover(s, key, now, cutoff):
                    by = row.body.get("revoked_by")
                    take = by if isinstance(by, str) else "unknown"
        if take is not None:
            return await _winner(state, snap, key, revoked_by=take, actor=actor, repaired=True)
        if memo_seq is not None:
            if await _memo_is_valid(state, snap, memo_seq):
                return Recorded(int(memo_seq), False)  # type: ignore[call-overload]
            async with db_tx(state) as s:  # corruption: discard the memo and record again
                await delete_key(s, key)
            log_event("revoke_repair_failed", engagement_id=snap.id, reason="memo_corrupt")
            continue
        if loop.time() >= t_end:
            raise _unavailable()
        await asyncio.sleep(t.claim_poll_s)


async def revoke_engagement(state: AppState, principal: Principal, engagement_id: str,
                            reason: str) -> tuple[datetime, int]:
    """The whole revoke path. Raises 404 for unknown or foreign ids (nothing written)."""
    now = state.clock.now()
    async with db_tx(state) as s:
        await get_engagement(s, engagement_id, principal.org_id)  # scoped: 404 before any write
        effected = await revoke_effect(s, engagement_id=engagement_id, org_id=principal.org_id,
                                       now=now, reason=reason)
        if effected:
            await transition_scans(s, org_id=principal.org_id, to="cancelled",
                                   frm=LIVE_SCAN_STATUSES, engagement_id=engagement_id)
            await claim_insert(s, key=memo_key(principal.org_id, engagement_id),
                               org_id=principal.org_id, rhash=MEMO_HASH, now=now,
                               body={"revoked_by": principal.api_key_id})
    async with db_read(state) as s:
        snap = await get_engagement(s, engagement_id, principal.org_id)
    try:
        rec = await ensure_revoked_entry(
            state, snap, actor=principal.actor, revoked_by=principal.api_key_id,
            owns_claim=effected)
    except ProblemError:
        log_event("revoke_unrecorded", engagement_id=engagement_id)
        raise
    return snap.revoked_at or now, rec.seq


async def repair_best_effort(state: AppState, snap: EngagementSnapshot, actor: str) -> None:
    """Scan-creation REVOKED branch: make sure the revoke is on the ledger. Never changes the
    response; failures are only logged."""
    try:
        await ensure_revoked_entry(state, snap, actor=actor)
    except Exception:  # noqa: BLE001
        log_event("revoke_repair_failed", engagement_id=snap.id, reason="scan_branch")


async def reconcile_revokes(state: AppState) -> int:
    """Startup reconciliation (system context, cross-org by design): record revokes from the last
    7 days that have no ledger entry. Returns the number of entries newly appended."""
    from vulnscope.api.limits import MAX_RECONCILE_ROWS, RECONCILE_DAYS

    cutoff = state.clock.now() - timedelta(days=RECONCILE_DAYS)
    async with db_read(state) as s:
        rows: list[Any] = list((await s.execute(
            select(Engagement).where(Engagement.status == "revoked",
                                     Engagement.revoked_at > cutoff)
            .order_by(Engagement.revoked_at.desc()).limit(MAX_RECONCILE_ROWS))).scalars())
        snaps = [snapshot_of(r) for r in rows]
    appended = 0
    for snap in snaps:
        try:
            rec = await ensure_revoked_entry(state, snap, actor="system")
            appended += 1 if rec.appended else 0
        except ProblemError:
            log_event("revoke_repair_failed", engagement_id=snap.id, reason="reconcile")
    log_event("reconcile_done", count=appended)
    return appended
