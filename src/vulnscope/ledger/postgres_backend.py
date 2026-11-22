"""PostgreSQL ``ChainBackend`` and ``CheckpointStore``: the ONLY ledger module that imports
sqlalchemy or ``vulnscope.models``.

Append protocol (ADR-0005 (d)): ONE connection and ONE transaction per append, ``READ COMMITTED``
(load-bearing for the first-append race), never committed or released between steps:

  0. ``set_config(..., true)``: ``lock_timeout``, ``statement_timeout``,
     ``idle_in_transaction_session_timeout`` (transaction-local, like ``SET LOCAL``)
  1. ``INSERT INTO chain_heads ... ON CONFLICT (chain_id) DO NOTHING``
  2. ``SELECT seq, head_hash FROM chain_heads WHERE chain_id = :c FOR UPDATE``  (row lock)
  3. cross-check against ``ledger_entries`` (``head_diverged`` fails loud, F7), compute the hash
  4. ``INSERT INTO ledger_entries``
  5. ``UPDATE chain_heads``
  COMMIT

Seqs are exactly 0..N-1 because the row lock of step 2 is held until COMMIT. ``UNIQUE(chain_id,
seq)`` is the independent backstop. The application adds NO process lock (correctness must hold
across processes and engines); the per-chain gate below is fairness only.

The backend never issues ``UPDATE``/``DELETE``/``TRUNCATE`` on ``ledger_entries`` or
``checkpoints`` (the app role does not hold those privileges and a trigger forbids them). There are
no automatic retries (a retry could double-append) and no fallback path. Errors are sanitized: only
a fixed operation, a code and a SQLSTATE leave this module (never SQL, parameters or payload), the
error is raised OUTSIDE the ``except`` block (no ``__context__``) and has no ``__cause__``.
Local-capturing crash tools must not be enabled on ``vulnscope.ledger`` (ADR-0005).
"""
from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from functools import partial
from typing import Any, Final, cast

from sqlalchemy import Row, Table, TextClause, func, insert, select, text, update
from sqlalchemy import exc as sa_exc
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine
from sqlalchemy.sql import Select
from sqlalchemy.sql.dml import Insert, Update

from vulnscope.ledger.canonical import (
    LEDGER_SCHEMA_VERSION,
    MAX_SEQ,
    PreparedEntry,
    compute_record_hash,
    genesis_hash,
    prepare_append,
    validate_chain_id,
)
from vulnscope.ledger.checkpoint import MAX_SCAN_ROWS, check_signature
from vulnscope.ledger.errors import (
    CanonicalizationError,
    LedgerStorageError,
    StorageCode,
    StorageOperation,
)
from vulnscope.ledger.signer import SignatureVerifier
from vulnscope.ledger.types import Checkpoint, LedgerEntry
from vulnscope.models.ledger_models import ChainHeadRow, CheckpointRow, LedgerEntryRow

_ENTRIES: Final = cast(Table, LedgerEntryRow.__table__)
_HEADS: Final = cast(Table, ChainHeadRow.__table__)
_CPS: Final = cast(Table, CheckpointRow.__table__)


# ------------------------------------------------------------------------------ statements
def stmt_set_timeouts() -> TextClause:
    return text(
        "SELECT set_config('lock_timeout', CAST(:lt AS text), true), "
        "set_config('statement_timeout', CAST(:st AS text), true), "
        "set_config('idle_in_transaction_session_timeout', CAST(:it AS text), true)"
    )


def stmt_ensure_head(chain_id: str, genesis: str) -> Insert:
    return (
        pg_insert(_HEADS)
        .values(chain_id=chain_id, seq=-1, head_hash=genesis)
        .on_conflict_do_nothing(index_elements=["chain_id"])
    )


def stmt_lock_head(chain_id: str) -> Select[tuple[int, str]]:
    return (
        select(_HEADS.c.seq, _HEADS.c.head_hash)
        .where(_HEADS.c.chain_id == chain_id)
        .with_for_update()
    )


def stmt_tail_check(chain_id: str, head_seq: int) -> Select[tuple[int, str]]:
    return (
        select(_ENTRIES.c.seq, _ENTRIES.c.record_hash)
        .where(_ENTRIES.c.chain_id == chain_id, _ENTRIES.c.seq >= max(head_seq, 0))
        .order_by(_ENTRIES.c.seq)
        .limit(2)
    )


def stmt_insert_entry(p: PreparedEntry, seq: int, prev_hash: str, record_hash: str) -> Insert:
    return insert(_ENTRIES).values(
        id=str(uuid.uuid4()),
        schema_version=LEDGER_SCHEMA_VERSION,
        chain_id=p.chain_id,
        seq=seq,
        kind=p.kind,
        actor=p.actor,
        payload=p.payload,
        ts=p.ts,
        prev_hash=prev_hash,
        record_hash=record_hash,
    )


def stmt_update_head(chain_id: str, seq: int, head_hash: str) -> Update:
    return update(_HEADS).where(_HEADS.c.chain_id == chain_id).values(seq=seq, head_hash=head_hash)


_ENTRY_COLUMNS: Final = (
    _ENTRIES.c.schema_version,
    _ENTRIES.c.chain_id,
    _ENTRIES.c.seq,
    _ENTRIES.c.kind,
    _ENTRIES.c.actor,
    _ENTRIES.c.payload,
    _ENTRIES.c.ts,
    _ENTRIES.c.prev_hash,
    _ENTRIES.c.record_hash,
)


def stmt_read_batch(chain_id: str, start_seq: int, batch: int) -> Select[tuple[object, ...]]:
    return (
        select(*_ENTRY_COLUMNS)
        .where(_ENTRIES.c.chain_id == chain_id, _ENTRIES.c.seq >= start_seq)
        .order_by(_ENTRIES.c.seq.asc())
        .limit(batch)
    )


def stmt_head(chain_id: str) -> Select[tuple[object, ...]]:
    return (
        select(*_ENTRY_COLUMNS)
        .where(_ENTRIES.c.chain_id == chain_id)
        .order_by(_ENTRIES.c.seq.desc())
        .limit(1)
    )


def stmt_count(chain_id: str) -> Select[tuple[int]]:
    return select(func.count()).select_from(_ENTRIES).where(_ENTRIES.c.chain_id == chain_id)


def stmt_insert_checkpoint(cp: Checkpoint) -> Insert:
    return insert(_CPS).values(
        id=str(uuid.uuid4()),
        chain_id=cp.chain_id,
        seq=cp.seq,
        head_hash=cp.head_hash,
        ts=cp.ts,
        signature=cp.signature,
    )


def stmt_checkpoints_newest(chain_id: str, limit: int) -> Select[tuple[object, ...]]:
    return (
        select(_CPS.c.chain_id, _CPS.c.seq, _CPS.c.head_hash, _CPS.c.ts, _CPS.c.signature)
        .where(_CPS.c.chain_id == chain_id)
        .order_by(_CPS.c.seq.desc(), _CPS.c.ts.desc())
        .limit(limit)
    )


# ------------------------------------------------------------------------------ error mapping
class _AppendAbort(Exception):
    """Internal: abort (and roll back) the append transaction with a fixed code."""

    def __init__(self, code: StorageCode) -> None:
        super().__init__(code)
        self.code: StorageCode = code


_SQLSTATE_CODES: Final[dict[str, StorageCode]] = {
    "55P03": "lock_timeout",
    "57014": "statement_timeout",
    "23505": "unique_violation",
    "42501": "insufficient_privilege",
    "P0001": "append_only_violation",
    "40001": "serialization",
    "40P01": "serialization",
}


def _sqlstate(exc: BaseException) -> str | None:
    """SQLSTATE only, from ``orig.pgcode`` / ``sqlstate`` / ``orig.__cause__.sqlstate``. Nothing
    else of the driver error is ever read (``detail`` and ``parameters`` can hold payload)."""
    cur: BaseException | None = exc
    for _ in range(4):
        if cur is None:
            return None
        for name in ("sqlstate", "pgcode"):
            v = getattr(cur, name, None)
            if type(v) is str and len(v) == 5 and v.isascii() and v.isalnum():
                return v
        nxt = getattr(cur, "orig", None)
        cur = nxt if isinstance(nxt, BaseException) else cur.__cause__
    return None


def _storage_error(operation: StorageOperation, exc: Exception) -> LedgerStorageError:
    """Build the sanitized error. Has no reference to ``exc`` or to anything it carries."""
    if isinstance(exc, _AppendAbort):
        return LedgerStorageError(operation, exc.code, None)
    state = _sqlstate(exc)
    code: StorageCode
    if state is not None and state in _SQLSTATE_CODES:
        code = _SQLSTATE_CODES[state]
    elif state is not None and state.startswith("08"):
        code = "connection"
    elif isinstance(exc, sa_exc.TimeoutError):
        code = "pool_timeout"
    elif isinstance(exc, OSError | sa_exc.InterfaceError) or getattr(
        exc, "connection_invalidated", False
    ):
        code = "connection"
    else:
        code = "other"
    return LedgerStorageError(operation, code, state)


async def _attempt[T](
    operation: StorageOperation, fn: Callable[[], Awaitable[T]]
) -> tuple[T | None, LedgerStorageError | None]:
    """Run ``fn``; map any ``Exception`` to a sanitized error that is RETURNED (the caller raises
    it outside any handler). ``BaseException`` (``CancelledError``) passes through untouched."""
    try:
        return await fn(), None
    except Exception as exc:  # noqa: BLE001 - sanitized below, see module docstring
        return None, _storage_error(operation, exc)


# ------------------------------------------------------------------------------ helpers
def _utc(ts: datetime) -> datetime:
    return ts.replace(tzinfo=UTC) if ts.tzinfo is None else ts.astimezone(UTC)


def _row_to_entry(r: Row[Any]) -> LedgerEntry:
    """Rebuild an entry exactly as stored (column order of ``_ENTRY_COLUMNS``). Nothing is
    repaired or de-duplicated: ``verify`` must see what is in the table."""
    return LedgerEntry(
        schema_version=r[0],
        chain_id=r[1],
        seq=r[2],
        kind=r[3],
        actor=r[4],
        payload=r[5],
        ts=_utc(r[6]),
        prev_hash=r[7],
        record_hash=r[8],
    )


class _Gate:
    __slots__ = ("refs", "sem")

    def __init__(self, waiters: int) -> None:
        self.refs = 0
        self.sem = asyncio.Semaphore(waiters)


class PostgresChainBackend:
    """Loop-affine like its engine: one event loop per backend instance."""

    def __init__(
        self,
        engine: AsyncEngine,
        *,
        lock_timeout_ms: int = 2_000,
        statement_timeout_ms: int = 15_000,
        read_batch: int = 500,
        max_waiters_per_chain: int = 4,
    ) -> None:
        for v in (lock_timeout_ms, statement_timeout_ms, read_batch, max_waiters_per_chain):
            if type(v) is not int or v <= 0:
                raise ValueError("backend limits must be positive integers")
        self._engine = engine
        self._timeouts = {
            "lt": str(lock_timeout_ms),
            "st": str(statement_timeout_ms),
            "it": str(statement_timeout_ms),
        }
        self._read_batch = read_batch
        self._max_waiters = max_waiters_per_chain
        self._gates: dict[str, _Gate] = {}

    # -- per-chain gate (fairness only; correctness lives in the database)
    @asynccontextmanager
    async def _gated(self, chain_id: str) -> AsyncIterator[None]:
        gate = self._gates.get(chain_id)
        if gate is None:
            gate = self._gates[chain_id] = _Gate(self._max_waiters)
        gate.refs += 1
        try:
            async with gate.sem:
                yield
        finally:
            gate.refs -= 1
            if gate.refs == 0:
                self._gates.pop(chain_id, None)

    async def _set_timeouts(self, conn: AsyncConnection) -> None:
        await conn.execute(stmt_set_timeouts(), self._timeouts)

    # -- append
    async def append(
        self,
        chain_id: str,
        kind: str,
        actor: str,
        payload: Mapping[str, object],
        ts: datetime,
    ) -> LedgerEntry:
        prepared = prepare_append(chain_id, kind, actor, payload, ts)  # before any connection
        async with self._gated(chain_id):
            entry, err = await _attempt("append", partial(self._append_tx, prepared))
        del prepared  # drop our reference to the payload before an error leaves this frame
        if err is not None:
            raise err
        assert entry is not None
        return entry

    async def _append_tx(self, p: PreparedEntry) -> LedgerEntry:
        genesis = genesis_hash(p.chain_id)
        async with self._engine.connect() as conn:
            await conn.execution_options(isolation_level="READ COMMITTED")
            async with conn.begin():
                await self._set_timeouts(conn)
                await conn.execute(stmt_ensure_head(p.chain_id, genesis))
                head = (await conn.execute(stmt_lock_head(p.chain_id))).one()
                head_seq, head_hash = int(head[0]), str(head[1])
                await self._check_head(conn, p.chain_id, head_seq, head_hash, genesis)
                seq = head_seq + 1
                if seq > MAX_SEQ:
                    raise _AppendAbort("seq_overflow")
                record_hash = compute_record_hash(
                    schema_version=LEDGER_SCHEMA_VERSION,
                    chain_id=p.chain_id,
                    seq=seq,
                    kind=p.kind,
                    actor=p.actor,
                    payload=p.payload,
                    ts=p.ts,
                    prev_hash=head_hash,
                )
                await conn.execute(stmt_insert_entry(p, seq, head_hash, record_hash))
                await conn.execute(stmt_update_head(p.chain_id, seq, record_hash))
        return LedgerEntry(
            schema_version=LEDGER_SCHEMA_VERSION,
            chain_id=p.chain_id,
            seq=seq,
            kind=p.kind,
            actor=p.actor,
            payload=p.payload,
            ts=p.ts,
            prev_hash=head_hash,
            record_hash=record_hash,
        )

    async def _check_head(
        self, conn: AsyncConnection, chain_id: str, head_seq: int, head_hash: str, genesis: str
    ) -> None:
        """Step 3b (F7): ``chain_heads`` must agree with ``ledger_entries``; otherwise fail loud."""
        rows = (await conn.execute(stmt_tail_check(chain_id, head_seq))).all()
        if head_seq < 0:
            consistent = not rows and head_hash == genesis
        else:
            consistent = (
                len(rows) == 1 and int(rows[0][0]) == head_seq and str(rows[0][1]) == head_hash
            )
        if not consistent:
            raise _AppendAbort("head_diverged")

    # -- reads (each batch in its own short transaction, connection released BEFORE yielding)
    async def _fetch(
        self, stmt: Select[tuple[object, ...]]
    ) -> list[LedgerEntry]:
        async with self._engine.connect() as conn:
            await conn.execution_options(isolation_level="READ COMMITTED")
            async with conn.begin():
                await self._set_timeouts(conn)
                rows = (await conn.execute(stmt)).all()
        return [_row_to_entry(r) for r in rows]

    async def read(
        self, chain_id: str, start_seq: int = 0, limit: int | None = None
    ) -> AsyncIterator[LedgerEntry]:
        validate_chain_id(chain_id)
        if type(start_seq) is not int or start_seq < 0:
            raise CanonicalizationError("invalid start_seq")
        if limit is not None and (type(limit) is not int or limit < 0):
            raise CanonicalizationError("invalid limit")
        seq = start_seq
        remaining = limit
        while remaining is None or remaining > 0:
            batch = self._read_batch if remaining is None else min(self._read_batch, remaining)
            stmt = stmt_read_batch(chain_id, seq, batch)
            rows, err = await _attempt("read", partial(self._fetch, stmt))
            if err is not None:
                raise err
            assert rows is not None
            for entry in rows:
                yield entry
            if len(rows) < batch:
                return
            seq = rows[-1].seq + 1
            if remaining is not None:
                remaining -= len(rows)

    async def head(self, chain_id: str) -> LedgerEntry | None:
        validate_chain_id(chain_id)
        rows, err = await _attempt("head", partial(self._fetch, stmt_head(chain_id)))
        if err is not None:
            raise err
        assert rows is not None
        return rows[0] if rows else None

    async def record_count(self, chain_id: str) -> int:
        validate_chain_id(chain_id)

        async def count() -> int:
            async with self._engine.connect() as conn:
                async with conn.begin():
                    await self._set_timeouts(conn)
                    return int((await conn.execute(stmt_count(chain_id))).scalar_one())

        n, err = await _attempt("count", count)
        if err is not None:
            raise err
        assert n is not None
        return n


class PostgresCheckpointStore:
    """Checkpoints table access. ``save`` is INSERT only; duplicate rows for one seq are tolerated
    (same head hash, both validly signed)."""

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def save(self, cp: Checkpoint) -> None:
        async def go() -> None:
            async with self._engine.connect() as conn:
                async with conn.begin():
                    await conn.execute(stmt_insert_checkpoint(cp))

        _, err = await _attempt("checkpoint_save", go)
        if err is not None:
            raise err

    async def _newest(self, chain_id: str, limit: int) -> list[Checkpoint]:
        async with self._engine.connect() as conn:
            async with conn.begin():
                rows = (await conn.execute(stmt_checkpoints_newest(chain_id, limit))).all()
        return [
            Checkpoint(
                chain_id=str(r[0]), seq=int(r[1]), head_hash=str(r[2]), ts=_utc(r[3]),
                signature=str(r[4]),
            )
            for r in rows
        ]

    async def latest(self, chain_id: str) -> Checkpoint | None:
        validate_chain_id(chain_id)
        rows, err = await _attempt("checkpoint_load", partial(self._newest, chain_id, 1))
        if err is not None:
            raise err
        assert rows is not None
        return rows[0] if rows else None

    async def latest_valid(
        self, chain_id: str, verifier: SignatureVerifier
    ) -> tuple[Checkpoint | None, int]:
        validate_chain_id(chain_id)
        rows, err = await _attempt(
            "checkpoint_load", partial(self._newest, chain_id, MAX_SCAN_ROWS)
        )
        if err is not None:
            raise err
        assert rows is not None
        invalid = 0
        for cp in rows:
            if check_signature(cp, verifier):
                return cp, invalid
            invalid += 1
        return None, invalid
