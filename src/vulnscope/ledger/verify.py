"""Chain verification: a streaming, single-pass walk that never raises on tampered data.

Pure module (no sqlalchemy, fastapi, models, api). Result conventions (ADR-0005, io-contracts
"Verify response"):

* ``ok``: the walk completed and the checkpoint (if any) is consistent. ``first_bad_seq`` None.
* ``bad_record``: edit, insert, delete-in-the-middle, reorder, wrong chain/version/hash format,
  wrong linkage, a negative or non-integer seq, or an anchored-hash mismatch. ``first_bad_seq`` is
  the first anomalous seq; for an anchored mismatch it is ``checkpoint.seq`` and means "at or
  before this seq" (an upper bound on the first divergence).
* ``fork``: a duplicate seq. ``first_bad_seq`` is the duplicated seq. (Unreachable on PostgreSQL by
  construction, ``UNIQUE(chain_id, seq)``; kept for any other backend.)
* ``truncated``: fewer records than ``checkpoint.seq + 1``. ``first_bad_seq`` is the first MISSING
  seq (= the number of records found); the expected minimum count is ``checkpoint_seq + 1``.

``records`` counts the entries consumed by the walk INCLUDING the offending one.
``checkpoint_seq`` is the supplied checkpoint's seq whenever an authentic checkpoint was supplied,
so the unanchored tail length is ``records - checkpoint_seq - 1``. A checkpoint OLDER than the head
is normal (``ok``); one NEWER than the data is ``truncated``. Without a checkpoint a truncated tail
is undetectable by design (ADR-0003), as is an edited-and-rehashed tail. ``ts`` is writer-attested
(D6): monotonicity is not checked.

``verify`` raises ``CheckpointRejected`` for an unauthentic checkpoint (a caller error, never a
result code) and lets ``LedgerStorageError`` propagate (a database outage must not read as ``ok``).
"""
from __future__ import annotations

from dataclasses import dataclass

from vulnscope.ledger.canonical import (
    LEDGER_SCHEMA_VERSION,
    entry_record_hash,
    genesis_hash,
    is_hash,
)
from vulnscope.ledger.chain import ChainBackend
from vulnscope.ledger.checkpoint import check_signature
from vulnscope.ledger.errors import CheckpointRejected
from vulnscope.ledger.signer import SignatureVerifier
from vulnscope.ledger.types import Checkpoint, LedgerEntry, VerifyResult


@dataclass(frozen=True)
class WalkOutcome:
    bad: VerifyResult | None
    count: int  # entries consumed, including the offending one
    last_seq: int  # seq of the last GOOD entry (start_seq - 1 if none)
    last_hash: str  # its record_hash (the starting prev hash if none)
    anchor_hash: str | None  # record_hash of the entry at ``anchor_seq``


def _check_entry(e: LedgerEntry, chain_id: str, prev: str) -> bool:
    """True when ``e`` is a well-formed, correctly linked, correctly hashed entry of the chain."""
    try:
        return (
            e.chain_id == chain_id
            and type(e.schema_version) is int
            and e.schema_version == LEDGER_SCHEMA_VERSION
            and is_hash(e.prev_hash)
            and is_hash(e.record_hash)
            and e.prev_hash == prev
            and entry_record_hash(e) == e.record_hash
        )
    except Exception:  # noqa: BLE001 - tampered data must classify, never raise
        return False


async def walk_chain(
    chain_id: str,
    backend: ChainBackend,
    *,
    start_seq: int = 0,
    start_prev_hash: str | None = None,
    anchor_seq: int | None = None,
    limit: int | None = None,
) -> WalkOutcome:
    """Stream ``backend.read`` once, stopping at the FIRST anomaly (checks in the order of the
    design, section 4): seq order, then well-formedness, linkage and the entry's own hash."""
    expected = start_seq
    prev = start_prev_hash if start_prev_hash is not None else genesis_hash(chain_id)
    count = 0
    last_seq = start_seq - 1
    last_hash = prev
    anchor_hash: str | None = None
    bad: VerifyResult | None = None
    it = backend.read(chain_id, start_seq, limit)
    try:
        async for e in it:
            count += 1
            seq = e.seq
            if type(seq) is not int or seq < 0:
                bad = VerifyResult("bad_record", expected, count, None)  # malformed seq
            elif seq < expected:
                bad = VerifyResult("fork", seq, count, None)  # a seq already consumed
            elif seq > expected:
                bad = VerifyResult("bad_record", expected, count, None)  # gap: delete or reorder
            elif not _check_entry(e, chain_id, prev):
                bad = VerifyResult("bad_record", seq, count, None)
            if bad is not None:
                break
            prev = e.record_hash
            last_seq = seq
            last_hash = prev
            expected += 1
            if seq == anchor_seq:
                anchor_hash = prev
    finally:
        aclose = getattr(it, "aclose", None)
        if aclose is not None:
            await aclose()
    return WalkOutcome(bad, count, last_seq, last_hash, anchor_hash)


def _with_checkpoint(r: VerifyResult, cp_seq: int | None) -> VerifyResult:
    return VerifyResult(r.result, r.first_bad_seq, r.records, cp_seq)


def _authenticate(
    chain_id: str, checkpoint: Checkpoint, verifier: SignatureVerifier | None
) -> None:
    if verifier is None:
        raise CheckpointRejected("no_verifier")  # an unauthenticated anchor is never used
    if checkpoint.chain_id != chain_id:
        raise CheckpointRejected("wrong_chain")
    if not check_signature(checkpoint, verifier):
        raise CheckpointRejected("bad_signature")


async def verify(
    chain_id: str,
    backend: ChainBackend,
    checkpoint: Checkpoint | None = None,
    *,
    verifier: SignatureVerifier | None = None,
) -> VerifyResult:
    """Verify one chain, optionally against a signed checkpoint (see the module docstring for the
    result conventions). Caller-error check order: no_verifier, wrong_chain, bad_signature."""
    if checkpoint is not None:
        _authenticate(chain_id, checkpoint, verifier)
    cp_seq = checkpoint.seq if checkpoint is not None else None
    out = await walk_chain(chain_id, backend, anchor_seq=cp_seq)
    if out.bad is not None:
        return _with_checkpoint(out.bad, cp_seq)
    if checkpoint is not None:
        if out.count < checkpoint.seq + 1:
            return VerifyResult("truncated", out.count, out.count, cp_seq)  # first missing seq
        if out.anchor_hash != checkpoint.head_hash:
            return VerifyResult("bad_record", checkpoint.seq, out.count, cp_seq)  # upper bound
    return VerifyResult("ok", None, out.count, cp_seq)


__all__ = ["WalkOutcome", "verify", "walk_chain"]
