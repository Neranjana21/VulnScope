# ruff: noqa: E501
"""Checkpoint edge cases beyond the R1 files (design R2.5 R1-8), the export sink and the parser."""
from __future__ import annotations

import os
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vulnscope.ledger.checkpoint import (
    FileCheckpointSink,
    InMemoryCheckpointStore,
    checkpoint_from_text,
    checkpoint_to_line,
    maybe_checkpoint,
    sign_checkpoint,
)
from vulnscope.ledger.errors import CheckpointRefused, CheckpointRejected
from vulnscope.ledger.memory_backend import InMemoryChainBackend
from vulnscope.ledger.types import Checkpoint

CID = "engagement:cpunit"
T0 = datetime(2026, 11, 19, tzinfo=UTC)
KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))


class _Signer:
    public_key_hex = KEY.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()

    def sign(self, payload: bytes) -> bytes:
        return KEY.sign(payload)

    def verify(self, payload: bytes, signature: bytes) -> bool:
        try:
            KEY.public_key().verify(signature, payload)
        except Exception:
            return False
        return True


SIGNER = _Signer()


async def _chain(n: int) -> InMemoryChainBackend:
    b = InMemoryChainBackend()
    for i in range(n):
        await b.append(CID, "policy.decision", "system", {"i": i}, T0 + timedelta(seconds=i))
    return b


async def test_chain_shorter_than_the_stored_checkpoint_is_refused_as_truncated() -> None:
    long = await _chain(30)
    head = await long.head(CID)
    assert head is not None
    store = InMemoryCheckpointStore()
    await store.save(sign_checkpoint(CID, 29, head.record_hash, T0, SIGNER))
    short = await _chain(10)
    with pytest.raises(CheckpointRefused) as info:
        await maybe_checkpoint(CID, short, SIGNER, store=store, ts=T0, force=True)
    assert info.value.result is not None and info.value.result.result == "truncated"


async def test_equal_seq_with_a_different_hash_is_refused_and_equal_hash_is_not_due() -> None:
    b = await _chain(10)
    head = await b.head(CID)
    assert head is not None
    good = InMemoryCheckpointStore()
    await good.save(sign_checkpoint(CID, 9, head.record_hash, T0, SIGNER))
    assert await maybe_checkpoint(CID, b, SIGNER, store=good, ts=T0, force=True) is None
    bad = InMemoryCheckpointStore()
    await bad.save(sign_checkpoint(CID, 9, "ab" * 32, T0, SIGNER))
    with pytest.raises(CheckpointRefused) as info:
        await maybe_checkpoint(CID, b, SIGNER, store=bad, ts=T0, force=True)
    assert info.value.result is not None and info.value.result.result == "bad_record"


async def test_more_than_a_thousand_forged_rows_still_sign_from_genesis_and_report_the_count() -> None:
    b = await _chain(120)
    store = InMemoryCheckpointStore()
    for i in range(1_001):
        await store.save(Checkpoint(CID, 5_000 + i, "ab" * 32, T0, "cd" * 64))
    cp = await maybe_checkpoint(CID, b, SIGNER, store=store, ts=T0)
    assert cp is not None and cp.seq == 119
    base, invalid = await store.latest_valid(CID, SIGNER)
    assert base is None or base.seq == 119
    # the scan stopped at the cap before reaching the valid row: a fixed-text alarm count
    assert invalid >= 1_000 or (base is not None and invalid == 1_001)


async def test_checkpoint_ts_is_normalised_to_utc() -> None:
    from datetime import timezone

    tz = timezone(timedelta(hours=3))
    cp = sign_checkpoint(CID, 0, "ab" * 32, datetime(2026, 1, 1, 3, tzinfo=tz), SIGNER)
    assert cp.ts == datetime(2026, 1, 1, tzinfo=UTC) and cp.ts.utcoffset() == timedelta(0)


# ------------------------------------------------------------------ file sink
async def test_file_sink_appends_lines_with_owner_only_mode(tmp_path: Path) -> None:
    d = tmp_path / "export"
    d.mkdir(mode=0o700)
    sink = FileCheckpointSink(d / "cp.log")
    a = sign_checkpoint(CID, 99, "ab" * 32, T0, SIGNER)
    b = sign_checkpoint(CID, 199, "cd" * 32, T0, SIGNER)
    await sink.write(a)
    await sink.write(b)
    lines = (d / "cp.log").read_text().splitlines()
    assert [checkpoint_from_text(x) for x in lines] == [a, b]
    assert stat.S_IMODE(os.stat(d / "cp.log").st_mode) == 0o600


async def test_file_sink_refuses_symlink_and_unsafe_directory(tmp_path: Path) -> None:
    d = tmp_path / "export"
    d.mkdir(mode=0o700)
    target = tmp_path / "elsewhere.log"
    target.write_text("")
    (d / "cp.log").symlink_to(target)
    cp = sign_checkpoint(CID, 1, "ab" * 32, T0, SIGNER)
    with pytest.raises(OSError):
        await FileCheckpointSink(d / "cp.log").write(cp)
    os.chmod(d, 0o777)
    try:
        with pytest.raises(OSError):
            await FileCheckpointSink(d / "new.log").write(cp)
    finally:
        os.chmod(d, 0o700)
    assert target.read_text() == ""


# ------------------------------------------------------------------ strict text parser
def test_from_text_size_cap_is_checked_before_parsing() -> None:
    cp = sign_checkpoint(CID, 9, "ab" * 32, T0, SIGNER)
    line = checkpoint_to_line(cp)
    assert checkpoint_from_text(line) == cp
    with pytest.raises(CheckpointRejected):
        checkpoint_from_text(line, max_bytes=len(line.encode()) - 2)


@pytest.mark.parametrize(
    "text",
    ["", "\x00", "{}", '{"chain_id":"engagement:x"}', "\xff\xfe", "9" * 5000, "NaN", '{"seq":NaN}',
     '{"seq":1,"seq":2}', "[" * 3000, "\ud800"],
)
def test_from_text_rejects_hostile_input_with_fixed_text(text: str) -> None:
    with pytest.raises(CheckpointRejected) as info:
        checkpoint_from_text(text)
    assert info.value.reason == "malformed"
    assert info.value.__cause__ is None and str(info.value) == "checkpoint rejected: malformed"


def test_from_text_rejects_duplicate_keys_and_negative_or_float_seq() -> None:
    cp = sign_checkpoint(CID, 9, "ab" * 32, T0, SIGNER)
    good = checkpoint_to_line(cp).strip()
    for bad in (good.replace('"seq":9', '"seq":-1'), good.replace('"seq":9', '"seq":9.5'),
                good.replace('"seq":9', '"seq":true'), good.replace('"seq":9,', '"seq":9,"seq":9,')):
        with pytest.raises(CheckpointRejected):
            checkpoint_from_text(bad)
