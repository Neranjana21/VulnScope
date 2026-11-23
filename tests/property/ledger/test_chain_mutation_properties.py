# ruff: noqa: E501
"""Random chains: any single-field mutation is detected; deleting a non-tail entry is detected;
tail truncation is undetectable without a checkpoint and detected with a covering one."""
from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from dataclasses import replace
from datetime import UTC, datetime, timedelta

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from vulnscope.ledger.canonical import prepare_payload
from vulnscope.ledger.checkpoint import sign_checkpoint
from vulnscope.ledger.memory_backend import InMemoryChainBackend
from vulnscope.ledger.signer import Ed25519PublicVerifier
from vulnscope.ledger.types import Checkpoint, LedgerEntry
from vulnscope.ledger.verify import verify

CID = "engagement:propchain"
T0 = datetime(2026, 11, 19, tzinfo=UTC)
SETTINGS = settings(max_examples=120, deadline=None, suppress_health_check=[HealthCheck.too_slow])


class _List:
    def __init__(self, entries: list[LedgerEntry]) -> None:
        self.entries = entries

    async def append(self, *a: object, **k: object) -> LedgerEntry:
        raise NotImplementedError

    async def read(
        self, chain_id: str, start_seq: int = 0, limit: int | None = None
    ) -> AsyncIterator[LedgerEntry]:
        n = 0
        for e in list(self.entries):
            if e.seq < start_seq and e.seq >= 0:
                continue
            if limit is not None and n >= limit:
                return
            n += 1
            yield e

    async def head(self, chain_id: str) -> LedgerEntry | None:
        return self.entries[-1] if self.entries else None

    async def record_count(self, chain_id: str) -> int:
        return len(self.entries)


async def _chain(payloads: list[dict[str, object]]) -> list[LedgerEntry]:
    b = InMemoryChainBackend()
    for i, p in enumerate(payloads):
        await b.append(CID, "policy.decision", "system", p, T0 + timedelta(seconds=i))
    return [e async for e in b.read(CID)]


payloads_st = st.lists(
    st.dictionaries(st.sampled_from(["a", "b", "c"]), st.integers(0, 9), max_size=3),
    min_size=3, max_size=12,
)
FIELDS = ["payload", "kind", "actor", "ts", "prev_hash", "record_hash", "seq", "chain_id"]


@SETTINGS
@given(payloads=payloads_st, idx_seed=st.integers(0, 10_000), field=st.sampled_from(FIELDS))
def test_any_single_field_mutation_is_detected_at_that_seq(
    payloads: list[dict[str, object]], idx_seed: int, field: str
) -> None:
    async def go() -> tuple[str, int | None, int]:
        es = await _chain(payloads)
        i = idx_seed % len(es)
        e = es[i]
        new = {
            "payload": {"mut": 1}, "kind": "scan.x", "actor": "user:z",
            "ts": e.ts + timedelta(microseconds=1), "prev_hash": "0" * 64,
            "record_hash": "1" * 64, "seq": e.seq + 50, "chain_id": "engagement:other",
        }[field]
        es[i] = replace(e, **{field: new})
        r = await verify(CID, _List(es))  # type: ignore[arg-type]
        return r.result, r.first_bad_seq, i

    result, bad, i = asyncio.run(go())
    assert result == "bad_record" and bad == i


@SETTINGS
@given(payloads=payloads_st, idx_seed=st.integers(0, 10_000))
def test_deleting_any_non_tail_entry_is_a_bad_record_at_that_seq(
    payloads: list[dict[str, object]], idx_seed: int
) -> None:
    async def go() -> tuple[str, int | None, int]:
        es = await _chain(payloads)
        i = idx_seed % (len(es) - 1)  # never the tail
        del es[i]
        r = await verify(CID, _List(es))  # type: ignore[arg-type]
        return r.result, r.first_bad_seq, i

    result, bad, i = asyncio.run(go())
    assert result == "bad_record" and bad == i


@SETTINGS
@given(payloads=payloads_st, cut_seed=st.integers(0, 10_000))
def test_tail_truncation_is_ok_without_a_checkpoint_and_truncated_with_one(
    payloads: list[dict[str, object]], cut_seed: int
) -> None:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))

    class _Signer:
        public_key_hex = key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()

        def sign(self, payload: bytes) -> bytes:
            return key.sign(payload)

        def verify(self, payload: bytes, signature: bytes) -> bool:
            return True

    async def go() -> tuple[str, str, int | None, int, int]:
        es = await _chain(payloads)
        cp: Checkpoint = sign_checkpoint(CID, es[-1].seq, es[-1].record_hash, T0, _Signer())
        keep = 1 + cut_seed % (len(es) - 1)  # drop at least one tail entry
        cut = es[:keep]
        plain = await verify(CID, _List(cut))  # type: ignore[arg-type]
        anchored = await verify(
            CID, _List(cut), cp,  # type: ignore[arg-type]
            verifier=Ed25519PublicVerifier.from_hex(_Signer.public_key_hex),
        )
        return plain.result, anchored.result, anchored.first_bad_seq, keep, anchored.checkpoint_seq or 0

    plain, anchored, first_missing, keep, cp_seq = asyncio.run(go())
    assert plain == "ok" and anchored == "truncated" and first_missing == keep
    assert cp_seq == len(payloads) - 1


def test_prepare_payload_matches_what_the_backend_returns() -> None:
    async def go() -> None:
        es = await _chain([{"a": 1}])
        assert dict(es[0].payload) == prepare_payload({"a": 1})

    asyncio.run(go())
