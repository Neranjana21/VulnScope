"""``ChainBackend`` Protocol -- async, per docs/gates/slice0-plan.md
Section 3.2/3.7/3.8 (corrected once ``asyncpg`` was approved: ``asyncpg``
has no synchronous SQLAlchemy engine path, so every method here is
``async``).

Built in Task 0 (moved here from Task B to fix pre-gate finding SEC-4):
``policy/decide_and_record.py`` (Task A) depends on this Protocol, not on
any concrete backend, so Task A is never blocked on Task B's
``InMemoryChainBackend``/``PostgresChainBackend`` implementations landing
first. Pure Protocol/typing module -- no ``sqlalchemy``/``fastapi``/
``models``/``api`` import, enforced by
``tests/unit/test_module_boundaries.py``.
"""
from __future__ import annotations

from collections.abc import AsyncIterator, Mapping
from datetime import datetime
from typing import Protocol

from vulnscope.ledger.types import LedgerEntry


class ChainBackend(Protocol):
    """Append-only, per-chain hash-chain storage. Implementations
    (``InMemoryChainBackend``, ``PostgresChainBackend``, Task B) must
    serialize concurrent ``append()`` calls for one ``chain_id`` (D1);
    chains are independent so there is no cross-chain lock contention.
    """

    async def append(
        self,
        chain_id: str,
        kind: str,
        actor: str,
        payload: Mapping[str, object],
        ts: datetime,
    ) -> LedgerEntry: ...

    async def read(
        self, chain_id: str, start_seq: int = 0, limit: int | None = None
    ) -> AsyncIterator[LedgerEntry]: ...

    async def head(self, chain_id: str) -> LedgerEntry | None: ...

    async def record_count(self, chain_id: str) -> int: ...
