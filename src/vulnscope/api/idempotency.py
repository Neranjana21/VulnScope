"""Idempotency (design 5, PD-11, PD-12). No migration: the existing ``idempotency_keys`` table.

Claim-then-finalize: ``response_status = 0`` marks an in-progress claim. Every database operation
here is its own short transaction; a transaction is never open across a ledger call.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import delete, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from vulnscope.api.db import db_tx
from vulnscope.api.limits import IDEMPOTENCY_TTL_S, MAX_KEY_LEN
from vulnscope.api.problem import Detail, ProblemError
from vulnscope.api.state import AppState
from vulnscope.errors import ReasonCode
from vulnscope.models.idempotency import IdempotencyKeyRow

_KEY_RE = re.compile(r"[\x21-\x7e]{1,255}")


# Client Idempotency-Keys that may never be used (DE-01). The revoke recorder keeps its memo row in
# this table under a key derived from a DIFFERENT preimage namespace (``revoke-memo-v1:``), which no
# client key can reach because every client preimage starts with ``idem-v1:``. These prefixes are
# also refused up front, so a client cannot even stage the old ``revoke-record:<id>`` shape.
# Lowercase; matching is case-insensitive.
RESERVED_KEY_PREFIXES = ("revoke-record:", "revoke-memo-")


def storage_preimage(org_id: str, raw_key: str) -> str:
    return f"idem-v1:{len(org_id)}:{org_id}:{raw_key}"


def storage_key(org_id: str, raw_key: str) -> str:
    """Injective for any org id content: ``idem-v1:<len(org)>:<org>:<key>``, SHA-256 hex."""
    return hashlib.sha256(storage_preimage(org_id, raw_key).encode()).hexdigest()


def request_hash(method: str, path: str, tree: Any) -> str:
    canon = json.dumps([method, path, tree], sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True)
    return hashlib.sha256(canon.encode("ascii")).hexdigest()


def parse_key_header(values: Sequence[str]) -> str | None:
    if not values:
        return None
    if len(values) != 1 or not _KEY_RE.fullmatch(values[0]) or len(values[0]) > MAX_KEY_LEN:
        raise ProblemError(422, ReasonCode.INVALID_REQUEST, Detail.BAD_REQUEST)
    if values[0].lower().startswith(RESERVED_KEY_PREFIXES):
        raise ProblemError(422, ReasonCode.INVALID_REQUEST, Detail.BAD_REQUEST)
    return values[0]


# ---- row primitives (the caller owns the transaction) ------------------------------------------
@dataclass(frozen=True)
class IdemRow:
    key: str
    org_id: str
    request_hash: str
    status: int
    body: dict[str, Any]
    created_at: datetime


async def claim_insert(session: AsyncSession, *, key: str, org_id: str, rhash: str, now: datetime,
                       body: dict[str, Any] | None = None) -> bool:
    stmt = (pg_insert(IdempotencyKeyRow)
            .values(key=key, org_id=org_id, request_hash=rhash, response_body=body or {},
                    response_status=0, created_at=now)
            .on_conflict_do_nothing(index_elements=["key"])
            .returning(IdempotencyKeyRow.key))
    return (await session.execute(stmt)).first() is not None


async def read_row(session: AsyncSession, key: str) -> IdemRow | None:
    r = (await session.execute(select(IdempotencyKeyRow).where(IdempotencyKeyRow.key == key)
                               )).scalar_one_or_none()
    if r is None:
        return None
    return IdemRow(r.key, r.org_id, r.request_hash, r.response_status, dict(r.response_body),
                   r.created_at)


async def delete_expired(session: AsyncSession, key: str, cutoff: datetime) -> None:
    await session.execute(delete(IdempotencyKeyRow).where(
        IdempotencyKeyRow.key == key, IdempotencyKeyRow.created_at < cutoff))


async def takeover(session: AsyncSession, key: str, now: datetime, cutoff: datetime) -> bool:
    res = await session.execute(
        update(IdempotencyKeyRow)
        .where(IdempotencyKeyRow.key == key, IdempotencyKeyRow.response_status == 0,
               IdempotencyKeyRow.created_at < cutoff)
        .values(created_at=now).returning(IdempotencyKeyRow.key))
    return res.first() is not None


async def finalize(session: AsyncSession, key: str, status: int, body: dict[str, Any]) -> bool:
    res = await session.execute(
        update(IdempotencyKeyRow)
        .where(IdempotencyKeyRow.key == key, IdempotencyKeyRow.response_status == 0)
        .values(response_status=status, response_body=body).returning(IdempotencyKeyRow.key))
    return res.first() is not None


async def delete_claim(session: AsyncSession, key: str) -> None:
    await session.execute(delete(IdempotencyKeyRow).where(
        IdempotencyKeyRow.key == key, IdempotencyKeyRow.response_status == 0))


async def delete_key(session: AsyncSession, key: str) -> None:
    """Unconditional delete of one row (corrupt revoke memo)."""
    await session.execute(delete(IdempotencyKeyRow).where(IdempotencyKeyRow.key == key))


async def mark_stale(session: AsyncSession, key: str, when: datetime) -> None:
    """Release an in-progress claim WITHOUT losing its body (revoke memo keeps ``revoked_by``)."""
    await session.execute(
        update(IdempotencyKeyRow)
        .where(IdempotencyKeyRow.key == key, IdempotencyKeyRow.response_status == 0)
        .values(created_at=when))


# ---- high level ---------------------------------------------------------------------------------
@dataclass(frozen=True)
class Won:
    key: str


@dataclass(frozen=True)
class Replay:
    status: int
    body: dict[str, Any]


@dataclass(frozen=True)
class Conflict:
    pass


@dataclass(frozen=True)
class InProgress:
    pass


Outcome = Won | Replay | Conflict | InProgress


async def acquire(state: AppState, *, org_id: str, raw_key: str, rhash: str) -> Outcome:
    """Claim ``raw_key`` for ``org_id``; replay, conflict, or wait for the winner (polling)."""
    key = storage_key(org_id, raw_key)
    t = state.timeouts
    loop = asyncio.get_running_loop()
    t_end = loop.time() + t.claim_wait_s
    while True:
        async with db_tx(state) as s:
            now = state.clock.now()
            await delete_expired(s, key, now - timedelta(seconds=IDEMPOTENCY_TTL_S))
            if await claim_insert(s, key=key, org_id=org_id, rhash=rhash, now=now):
                return Won(key)
            row = await read_row(s, key)
            if row is not None:
                if row.org_id != org_id:  # cannot happen: the key embeds the org; treat as fault
                    raise RuntimeError("idempotency row org mismatch")
                if row.request_hash != rhash:
                    return Conflict()
                if row.status > 0:
                    return Replay(row.status, row.body)
                cutoff = now - timedelta(seconds=t.claim_stale_s)
                if row.created_at < cutoff and await takeover(s, key, now, cutoff):
                    return Won(key)
        if loop.time() >= t_end:
            return InProgress()
        await asyncio.sleep(t.claim_poll_s)


async def release(state: AppState, key: str) -> None:
    """Best-effort release of an in-progress claim (winner failure, non-storable outcome)."""
    try:
        async with db_tx(state) as s:
            await delete_claim(s, key)
    except Exception:  # noqa: BLE001 - release is best effort; the claim goes stale in 60 s
        return


async def finalize_standalone(state: AppState, key: str, status: int,
                              body: dict[str, Any]) -> bool:
    async with db_tx(state) as s:
        return await finalize(s, key, status, body)
