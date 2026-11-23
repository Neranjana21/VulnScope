# ruff: noqa: E501
"""PostgresCheckpointStore end to end: save/latest, maybe_checkpoint at 100 with a real signer and
the export sink, then tamper as the admin role and observe verify with the checkpoint."""
from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ledger_pg_support import admin_exec, open_backend, sql_lit

from vulnscope.ledger.checkpoint import FileCheckpointSink, checkpoint_from_text, maybe_checkpoint
from vulnscope.ledger.postgres_backend import PostgresCheckpointStore
from vulnscope.ledger.signer import Ed25519FileSigner, Ed25519PublicVerifier
from vulnscope.ledger.types import Checkpoint
from vulnscope.ledger.verify import verify

pytestmark = pytest.mark.integration
T0 = datetime(2026, 11, 19, 8, 30, tzinfo=UTC)
SEED = bytes(range(32))


def _signer(tmp_path: Path) -> Ed25519FileSigner:
    d = tmp_path / "k"
    d.mkdir(mode=0o700)
    p = d / "ledger.pem"
    pem = Ed25519PrivateKey.from_private_bytes(SEED).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(pem)
    return Ed25519FileSigner.load(p)


async def test_save_latest_and_latest_valid(ledger_db: Any, tmp_path: Path) -> None:
    cid = f"engagement:{uuid.uuid4()}"
    signer = _signer(tmp_path)
    engine, _ = await open_backend(ledger_db)
    try:
        store = PostgresCheckpointStore(engine)
        assert await store.latest(cid) is None
        assert await store.latest_valid(cid, signer) == (None, 0)
        good = Checkpoint(cid, 9, "ab" * 32, T0, "00" * 64)
        await store.save(good)
        assert await store.latest(cid) == good
        base, invalid = await store.latest_valid(cid, signer)
        assert base is None and invalid == 1  # the stored signature is not valid
    finally:
        await engine.dispose()


async def test_checkpoint_at_100_sink_then_admin_truncation_is_detected(
    ledger_db: Any, tmp_path: Path
) -> None:
    cid = f"engagement:{uuid.uuid4()}"
    signer = _signer(tmp_path)
    out = tmp_path / "export"
    out.mkdir(mode=0o700)
    engine, backend = await open_backend(ledger_db)
    try:
        for i in range(120):
            await backend.append(cid, "policy.decision", "system", {"i": i}, T0 + timedelta(seconds=i))
        store = PostgresCheckpointStore(engine)
        sink = FileCheckpointSink(out / "checkpoints.log")
        cp = await maybe_checkpoint(cid, backend, signer, store=store, sink=sink, ts=T0)
        assert cp is not None and cp.seq == 119
        assert await store.latest(cid) == cp
        exported = [checkpoint_from_text(x) for x in (out / "checkpoints.log").read_text().splitlines()]
        assert exported == [cp]
        verifier = Ed25519PublicVerifier.from_hex(signer.public_key_hex)
        assert (await verify(cid, backend, cp, verifier=verifier)).result == "ok"
        # a second call within the interval is not due
        assert await maybe_checkpoint(cid, backend, signer, store=store, ts=T0) is None

        admin_exec(ledger_db, "ALTER TABLE ledger_entries DISABLE TRIGGER ledger_entries_no_mutate")
        try:
            admin_exec(ledger_db, f"DELETE FROM ledger_entries WHERE chain_id = {sql_lit(cid)} AND seq >= 100")
        finally:
            admin_exec(ledger_db, "ALTER TABLE ledger_entries ENABLE ALWAYS TRIGGER ledger_entries_no_mutate")
        res = await verify(cid, backend, exported[-1], verifier=verifier)
        assert (res.result, res.first_bad_seq, res.records, res.checkpoint_seq) == ("truncated", 100, 100, 119)
        plain = await verify(cid, backend)
        assert plain.result == "ok"  # the documented limitation without a checkpoint
    finally:
        await engine.dispose()
