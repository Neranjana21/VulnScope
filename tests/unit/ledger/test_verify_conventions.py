"""verify() conventions pinned (design section 4, F11): storage errors propagate, the docstring
states the result codes, fork, truncated first-missing-seq, anchored upper bound."""
from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import pytest

from vulnscope.ledger import verify as verify_module
from vulnscope.ledger.errors import CheckpointRejected, LedgerStorageError
from vulnscope.ledger.memory_backend import InMemoryChainBackend
from vulnscope.ledger.types import LedgerEntry
from vulnscope.ledger.verify import verify, walk_chain

CID = "engagement:vconv"
T0 = datetime(2026, 11, 19, tzinfo=UTC)


class _Failing:
    """A backend whose storage fails part-way through a read."""

    def __init__(self, good: list[LedgerEntry]) -> None:
        self.good = good

    async def append(self, *a: object, **k: object) -> LedgerEntry:
        raise NotImplementedError

    async def read(
        self, chain_id: str, start_seq: int = 0, limit: int | None = None
    ) -> AsyncIterator[LedgerEntry]:
        for e in self.good:
            yield e
        raise LedgerStorageError("read", "connection")

    async def head(self, chain_id: str) -> LedgerEntry | None:
        return None

    async def record_count(self, chain_id: str) -> int:
        return 0


async def test_a_storage_outage_is_an_error_never_ok() -> None:
    b = InMemoryChainBackend()
    for i in range(3):
        await b.append(CID, "policy.decision", "system", {"i": i}, T0 + timedelta(seconds=i))
    es = [e async for e in b.read(CID)]
    with pytest.raises(LedgerStorageError):
        await verify(CID, _Failing(es))  # type: ignore[arg-type]


async def test_walk_closes_the_backend_iterator_on_early_stop() -> None:
    closed: list[bool] = []

    class _Gen:
        async def append(self, *a: object, **k: object) -> LedgerEntry:
            raise NotImplementedError

        async def read(
            self, chain_id: str, start_seq: int = 0, limit: int | None = None
        ) -> AsyncIterator[LedgerEntry]:
            try:
                b = InMemoryChainBackend()
                for i in range(5):
                    await b.append(CID, "policy.decision", "system", {"i": i}, T0)
                es = [e async for e in b.read(CID)]
                es[1] = LedgerEntry(**{**es[1].__dict__, "kind": "scan.x"})
                for e in es:
                    yield e
            finally:
                closed.append(True)

        async def head(self, chain_id: str) -> LedgerEntry | None:
            return None

        async def record_count(self, chain_id: str) -> int:
            return 0

    out = await walk_chain(CID, _Gen())  # type: ignore[arg-type]
    assert out.bad is not None and out.bad.first_bad_seq == 1 and out.count == 2
    assert closed == [True]


def test_docstring_states_the_result_conventions() -> None:
    doc = " ".join((verify_module.__doc__ or "").split())  # undo line wrapping
    for phrase in ("first MISSING seq", "at or before", "duplicate seq", "checkpoint_seq + 1",
                   "undetectable by design", "CheckpointRejected"):
        assert phrase in doc, phrase


async def test_an_unauthenticated_checkpoint_is_rejected_before_any_read() -> None:
    from vulnscope.ledger.types import Checkpoint

    class _Never:
        async def read(self, *a: object, **k: object) -> AsyncIterator[LedgerEntry]:
            raise AssertionError("must not read")
            yield  # pragma: no cover

    with pytest.raises(CheckpointRejected) as info:
        await verify(CID, _Never(), Checkpoint("engagement:other", 0, "ab" * 32, T0, "cd" * 64))  # type: ignore[arg-type]
    assert info.value.reason == "no_verifier"
