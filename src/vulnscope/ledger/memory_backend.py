"""In-memory ``ChainBackend``: the twin of the PostgreSQL backend for unit tests and early work.

Pure, standard library only. Same validation, same sanitization and the same normalised round trip
as ``postgres_backend`` (both call ``canonical.prepare_append``). Thread-safe, not just
asyncio-safe: the critical section holds a ``threading.Lock`` and contains no ``await`` (an
``asyncio.Lock`` would bind to one event loop). Payloads are kept as canonical bytes so every read
returns a fresh dict (no aliasing) and the in-memory footprint per entry stays small.
"""
from __future__ import annotations

import json
import threading
from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass
from datetime import datetime

from vulnscope.ledger.canonical import (
    LEDGER_SCHEMA_VERSION,
    compute_record_hash,
    dumps_validated,
    genesis_hash,
    prepare_append,
    validate_chain_id,
)
from vulnscope.ledger.errors import CanonicalizationError
from vulnscope.ledger.types import LedgerEntry

_CHUNK = 1024


@dataclass(frozen=True, slots=True)
class _Stored:
    kind: str
    actor: str
    payload: bytes
    ts: datetime
    prev_hash: str
    record_hash: str


class InMemoryChainBackend:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._chains: dict[str, list[_Stored]] = {}

    @staticmethod
    def _entry(chain_id: str, seq: int, s: _Stored) -> LedgerEntry:
        return LedgerEntry(
            schema_version=LEDGER_SCHEMA_VERSION,
            chain_id=chain_id,
            seq=seq,
            kind=s.kind,
            actor=s.actor,
            payload=json.loads(s.payload),
            ts=s.ts,
            prev_hash=s.prev_hash,
            record_hash=s.record_hash,
        )

    async def append(
        self,
        chain_id: str,
        kind: str,
        actor: str,
        payload: Mapping[str, object],
        ts: datetime,
    ) -> LedgerEntry:
        prepared = prepare_append(chain_id, kind, actor, payload, ts)
        payload_bytes = dumps_validated(prepared.payload)
        genesis = genesis_hash(chain_id)
        with self._lock:  # no await inside: safe across threads and event loops
            chain = self._chains.setdefault(chain_id, [])
            seq = len(chain)
            prev = chain[-1].record_hash if chain else genesis
            record_hash = compute_record_hash(
                schema_version=LEDGER_SCHEMA_VERSION,
                chain_id=chain_id,
                seq=seq,
                kind=prepared.kind,
                actor=prepared.actor,
                payload=prepared.payload,
                ts=prepared.ts,
                prev_hash=prev,
            )
            stored = _Stored(
                prepared.kind, prepared.actor, payload_bytes, prepared.ts, prev, record_hash
            )
            chain.append(stored)
        return LedgerEntry(
            schema_version=LEDGER_SCHEMA_VERSION,
            chain_id=chain_id,
            seq=seq,
            kind=stored.kind,
            actor=stored.actor,
            payload=json.loads(payload_bytes),
            ts=stored.ts,
            prev_hash=prev,
            record_hash=record_hash,
        )

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
            take = _CHUNK if remaining is None else min(_CHUNK, remaining)
            with self._lock:  # copy at most one chunk of references, never the whole chain
                chain = self._chains.get(chain_id)
                chunk = chain[seq : seq + take] if chain else []
            if not chunk:
                return
            for offset, stored in enumerate(chunk):
                yield self._entry(chain_id, seq + offset, stored)
            seq += len(chunk)
            if remaining is not None:
                remaining -= len(chunk)

    async def head(self, chain_id: str) -> LedgerEntry | None:
        validate_chain_id(chain_id)
        with self._lock:
            chain = self._chains.get(chain_id)
            if not chain:
                return None
            seq, stored = len(chain) - 1, chain[-1]
        return self._entry(chain_id, seq, stored)

    async def record_count(self, chain_id: str) -> int:
        validate_chain_id(chain_id)
        with self._lock:
            return len(self._chains.get(chain_id, ()))
