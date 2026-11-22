"""Signed checkpoints: message format, signing cadence, stores and the exported line format.

Pure (standard library plus ``signer``); no sqlalchemy. The PostgreSQL store lives in
``postgres_backend``. A checkpoint asserts "at least ``seq + 1`` records, and this hash at ``seq``"
and is signed over a domain-separated message (it can never equal a record-hash input).

Rules (ADR-0005): a checkpoint is only ever signed over a segment that THIS call walked and
verified (the anchor must not launder tampering); the export sink is written BEFORE the store, so a
failed file write leaves the next call still due; stored rows with a bad signature are skipped and
counted, never trusted and never able to block anchoring; no ``checkpoint`` entry is appended to the
chain in Slice 0.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, Protocol, cast

from vulnscope.ledger.canonical import (
    MAX_SEQ,
    canonical_json,
    format_ts,
    is_hash,
    parse_ts,
    validate_chain_id,
)
from vulnscope.ledger.chain import ChainBackend
from vulnscope.ledger.errors import (
    CanonicalizationError,
    CheckpointRefused,
    CheckpointRejected,
)
from vulnscope.ledger.signer import LedgerSigner, SignatureVerifier
from vulnscope.ledger.types import Checkpoint, VerifyResult

CHECKPOINT_INTERVAL: Final = 100
MESSAGE_PREFIX: Final = b"vulnscope-checkpoint-v1\n"
MAX_SCAN_ROWS: Final = 1_000
_SIG_RE: Final = re.compile(r"[0-9a-f]{128}")
_LINE_KEYS: Final = frozenset({"chain_id", "head_hash", "seq", "signature", "ts"})
_log = logging.getLogger("vulnscope.ledger.checkpoint")


# ---- message and signature
def checkpoint_message(chain_id: str, seq: int, head_hash: str, ts: datetime) -> bytes:
    """The signed bytes: ``b"vulnscope-checkpoint-v1\\n" + canonical_json({...})``."""
    validate_chain_id(chain_id)
    if type(seq) is not int or seq < 0 or seq > MAX_SEQ:
        raise CanonicalizationError("invalid seq")
    if not is_hash(head_hash):
        raise CanonicalizationError("invalid hash")
    body = canonical_json(
        {"chain_id": chain_id, "head_hash": head_hash, "seq": seq, "ts": format_ts(ts)}
    )
    return MESSAGE_PREFIX + body


def sign_checkpoint(
    chain_id: str, seq: int, head_hash: str, ts: datetime, signer: LedgerSigner
) -> Checkpoint:
    message = checkpoint_message(chain_id, seq, head_hash, ts)
    return Checkpoint(
        chain_id=chain_id,
        seq=seq,
        head_hash=head_hash,
        ts=ts.astimezone(UTC),
        signature=signer.sign(message).hex(),
    )


def check_signature(cp: Checkpoint, verifier: SignatureVerifier) -> bool:
    """True only for a valid signature. Never raises: garbage in any field is simply ``False``."""
    try:
        sig = cp.signature
        if type(sig) is not str or not sig.isascii() or _SIG_RE.fullmatch(sig) is None:
            return False
        message = checkpoint_message(cp.chain_id, cp.seq, cp.head_hash, cp.ts)
        return verifier.verify(message, bytes.fromhex(sig)) is True
    except Exception:  # noqa: BLE001 - an unverifiable checkpoint is not authentic, never an error
        return False


# ---- exported line format
def checkpoint_to_line(cp: Checkpoint) -> str:
    """One canonical-JSON line (with trailing newline) for the external export file."""
    body = canonical_json(
        {
            "chain_id": cp.chain_id,
            "head_hash": cp.head_hash,
            "seq": cp.seq,
            "signature": cp.signature,
            "ts": format_ts(cp.ts),
        }
    )
    return body.decode("utf-8") + "\n"


def _reject_constant(_: str) -> object:
    raise ValueError("non-finite number")


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    out: dict[str, object] = {}
    for k, v in pairs:
        if k in out:
            raise ValueError("duplicate key")
        out[k] = v
    return out


def _parse_line(text: object, max_bytes: int) -> Checkpoint | None:
    """Strict parse. ``None`` for ANY failure; nothing about the input is kept or echoed."""
    try:
        if type(text) is not str or len(text) > max_bytes:
            return None
        if len(text.encode("utf-8")) > max_bytes or "\x00" in text:
            return None
        raw = json.loads(text, parse_constant=_reject_constant, object_pairs_hook=_no_duplicates)
        if type(raw) is not dict or set(raw) != _LINE_KEYS:
            return None
        chain_id, head_hash, seq, signature, ts = (
            raw["chain_id"],
            raw["head_hash"],
            raw["seq"],
            raw["signature"],
            raw["ts"],
        )
        if type(chain_id) is not str or type(ts) is not str or type(signature) is not str:
            return None
        if type(seq) is not int or seq < 0 or seq > MAX_SEQ or not is_hash(head_hash):
            return None
        if not signature.isascii() or _SIG_RE.fullmatch(signature) is None:
            return None
        validate_chain_id(chain_id)
        return Checkpoint(chain_id, seq, cast(str, head_hash), parse_ts(ts), signature)
    except Exception:  # noqa: BLE001 - includes RecursionError from hostile nesting
        return None


def checkpoint_from_text(text: str, *, max_bytes: int = 4096) -> Checkpoint:
    """Parse one exported line. Size is checked before parsing; every failure raises
    ``CheckpointRejected("malformed")`` with fixed text (never echoes input, no ``__cause__``)."""
    cp = _parse_line(text, max_bytes)
    if cp is None:
        raise CheckpointRejected("malformed")
    return cp


# ---- stores and sinks
class CheckpointStore(Protocol):
    async def save(self, cp: Checkpoint) -> None: ...

    async def latest(self, chain_id: str) -> Checkpoint | None: ...

    async def latest_valid(
        self, chain_id: str, verifier: SignatureVerifier
    ) -> tuple[Checkpoint | None, int]:
        """Newest checkpoint with a valid signature, and the number of invalid rows skipped above
        it (scans at most ``MAX_SCAN_ROWS`` rows, newest first)."""
        ...


class CheckpointSink(Protocol):
    async def write(self, cp: Checkpoint) -> None: ...


class InMemoryCheckpointStore:
    def __init__(self) -> None:
        self._rows: dict[str, list[Checkpoint]] = {}

    async def save(self, cp: Checkpoint) -> None:
        self._rows.setdefault(cp.chain_id, []).append(cp)

    def _ordered(self, chain_id: str) -> list[Checkpoint]:
        return sorted(self._rows.get(chain_id, []), key=lambda c: (c.seq, c.ts), reverse=True)

    async def latest(self, chain_id: str) -> Checkpoint | None:
        rows = self._ordered(chain_id)
        return rows[0] if rows else None

    async def latest_valid(
        self, chain_id: str, verifier: SignatureVerifier
    ) -> tuple[Checkpoint | None, int]:
        invalid = 0
        for cp in self._ordered(chain_id)[:MAX_SCAN_ROWS]:
            if check_signature(cp, verifier):
                return cp, invalid
            invalid += 1
        return None, invalid


def _append_line(path: Path, line: str) -> None:
    parent = os.path.dirname(os.fspath(path)) or "."
    dfd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        if os.fstat(dfd).st_mode & 0o022:
            raise OSError("checkpoint export directory is group or world writable")
    finally:
        os.close(dfd)
    fd = os.open(
        os.fspath(path),
        os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
    )
    try:
        os.write(fd, line.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)


class FileCheckpointSink:
    """Appends one canonical line per checkpoint to a file OUTSIDE the database (a separate volume
    or host is a deployment property; the path comes from trusted configuration only)."""

    def __init__(self, path: Path) -> None:
        self._path = path

    async def write(self, cp: Checkpoint) -> None:
        await asyncio.to_thread(_append_line, self._path, checkpoint_to_line(cp))


# ---- cadence
async def maybe_checkpoint(
    chain_id: str,
    backend: ChainBackend,
    signer: LedgerSigner,
    *,
    store: CheckpointStore,
    sink: CheckpointSink | None = None,
    ts: datetime,
    interval: int = CHECKPOINT_INTERVAL,
    force: bool = False,
) -> Checkpoint | None:
    """Sign a checkpoint when ``interval`` new records exist since the newest VALID one (or when
    ``force``). Only the new segment is walked (O(interval)); the walk is the authority: the pair
    that is signed is the last entry the walk verified, and it must equal the head seen at call
    time, otherwise ``CheckpointRefused`` (entries are immutable: a mismatch is tampering)."""
    from vulnscope.ledger.verify import walk_chain  # local import: verify imports this module

    head = await backend.head(chain_id)
    if head is None:
        return None
    base, invalid = await store.latest_valid(chain_id, signer)
    if invalid:
        _log.warning(
            "checkpoint store holds rows with invalid signatures",
            extra={"chain_id": chain_id, "invalid_count": invalid},
        )
    if base is not None:
        if head.seq < base.seq:
            raise CheckpointRefused(
                "chain_not_verified",
                VerifyResult("truncated", head.seq + 1, head.seq + 1, base.seq),
            )
        if head.seq == base.seq:
            if head.record_hash != base.head_hash:
                raise CheckpointRefused(
                    "chain_not_verified",
                    VerifyResult("bad_record", base.seq, head.seq + 1, base.seq),
                )
            return None  # nothing new to anchor
    last_seq = base.seq if base is not None else -1
    if not force and head.seq - last_seq < interval:
        return None
    start = last_seq + 1
    limit = head.seq - start + 1
    outcome = await walk_chain(
        chain_id,
        backend,
        start_seq=start,
        start_prev_hash=base.head_hash if base is not None else None,
        limit=limit,
    )
    if (
        outcome.bad is not None
        or outcome.last_seq != head.seq
        or outcome.last_hash != head.record_hash
    ):
        raise CheckpointRefused("chain_not_verified", outcome.bad)
    cp = sign_checkpoint(chain_id, outcome.last_seq, outcome.last_hash, ts, signer)
    if sink is not None:
        await sink.write(cp)  # outside the database FIRST; a failure saves nothing
    await store.save(cp)
    return cp
