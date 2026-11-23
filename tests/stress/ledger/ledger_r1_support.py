# ruff: noqa: E501
"""Shared helpers for the Task B R1 stress files (tamper matrix, checkpoint forgery, intake
isolation, hostile-payload denial, golden-vector conformance). R1: read-only for the implementer.

Design rules (docs/gates/task-b-design.md F13):
* Production modules are imported LAZILY (``mods()``), so a missing module is a per-test FAILURE
  (ModuleNotFoundError), never a collection error and never a skip.
* The reference functions below (``ref_*``) are a stdlib-only oracle for the wire format. They are
  cross-checked against a second engine (docs/gates/task-b-r1-vectors-crosscheck.md), so tamper
  tests do not depend on Task B's own canonicaliser to build valid or rehashed chains.
* Tamper tests use ``ListBackend`` (test-side double, no tamper hooks in production code).
"""
from __future__ import annotations

import asyncio
import hashlib
import importlib
import json
import os
import stat
from collections.abc import AsyncIterator, Mapping
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from vulnscope.ledger.types import Checkpoint, LedgerEntry

GOLDEN = Path(__file__).resolve().parents[2] / "fixtures" / "ledger_golden"
BASE_TS = datetime(2026, 11, 19, 8, 30, 0, tzinfo=UTC)
SEED1 = bytes(range(32))
SEED2 = bytes(range(32, 64))
SEED3 = bytes(range(64, 96))
HEX64 = frozenset("0123456789abcdef")


def golden(name: str) -> Any:
    return json.loads((GOLDEN / name).read_text(encoding="ascii"))


def mods() -> SimpleNamespace:
    """Import Task B modules at call time (red state = ModuleNotFoundError inside the test)."""
    names = ("canonical", "verify", "checkpoint", "signer", "memory_backend", "errors")
    return SimpleNamespace(**{n: importlib.import_module(f"vulnscope.ledger.{n}") for n in names})


# ---------------------------------------------------------------- reference oracle (stdlib only)
def ref_canon(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def ref_sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def ref_ts(ts: datetime) -> str:
    d = ts.astimezone(UTC)
    return "%04d-%02d-%02dT%02d:%02d:%02d.%06dZ" % (
        d.year, d.month, d.day, d.hour, d.minute, d.second, d.microsecond,
    )


def ref_genesis(chain_id: str) -> str:
    return ref_sha(("vulnscope-ledger-v1:" + chain_id).encode("utf-8"))


def ref_hash(e: LedgerEntry) -> str:
    doc = {
        "schema_version": e.schema_version, "chain_id": e.chain_id, "seq": e.seq, "kind": e.kind,
        "actor": e.actor, "payload": e.payload, "ts": ref_ts(e.ts), "prev_hash": e.prev_hash,
    }
    return ref_sha(e.prev_hash.encode("ascii") + ref_canon(doc))


def rehash(e: LedgerEntry, **changes: Any) -> LedgerEntry:
    """Copy with ``changes`` applied and a CORRECT self-hash (what an attacker with the format can do)."""
    new = replace(e, **changes)
    return replace(new, record_hash=ref_hash(new))


def ref_chain(chain_id: str, n: int, *, base_ts: datetime = BASE_TS) -> list[LedgerEntry]:
    out: list[LedgerEntry] = []
    prev = ref_genesis(chain_id)
    for i in range(n):
        e = LedgerEntry(
            schema_version=1, chain_id=chain_id, seq=i, kind="policy.decision",
            actor="system" if i % 2 == 0 else "user:alice",
            payload={"i": i, "target": f"h{i}.lab.test", "allowed": i % 3 != 0},
            ts=base_ts + timedelta(seconds=i), prev_hash=prev, record_hash="0" * 64,
        )
        e = replace(e, record_hash=ref_hash(e))
        out.append(e)
        prev = e.record_hash
    return out


def cascade(entries: list[LedgerEntry], start: int, **payload_edit: object) -> list[LedgerEntry]:
    """Rewrite entries[start:] (payload edited, every link and hash recomputed): a full cascade."""
    out = list(entries[:start])
    prev = out[-1].record_hash if out else ref_genesis(entries[0].chain_id)
    for e in entries[start:]:
        new = rehash(e, prev_hash=prev, payload={**e.payload, **payload_edit})
        out.append(new)
        prev = new.record_hash
    return out


class ListBackend:
    """ChainBackend double over a plain list (tamperable). Ignores ``chain_id`` on purpose."""

    def __init__(self, entries: list[LedgerEntry]) -> None:
        self.entries = list(entries)
        self.read_count = 0

    async def append(self, chain_id: str, kind: str, actor: str,
                     payload: Mapping[str, object], ts: datetime) -> LedgerEntry:
        raise NotImplementedError("ListBackend is read-only")

    async def read(self, chain_id: str, start_seq: int = 0,
                   limit: int | None = None) -> AsyncIterator[LedgerEntry]:
        n = 0
        for e in list(self.entries):
            if start_seq and e.seq < start_seq:
                continue
            if limit is not None and n >= limit:
                return
            n += 1
            self.read_count += 1
            yield e

    async def head(self, chain_id: str) -> LedgerEntry | None:
        return self.entries[-1] if self.entries else None

    async def record_count(self, chain_id: str) -> int:
        return len(self.entries)


# ---------------------------------------------------------------- keys and checkpoints
def write_key_file(tmp_path: Path, seed: bytes, name: str = "ledger.key") -> Path:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    d = tmp_path / f"keys_{name}"
    d.mkdir(mode=0o700, exist_ok=True)
    os.chmod(d, 0o700)
    p = d / name
    pem = Ed25519PrivateKey.from_private_bytes(seed).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(pem)
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600
    return p


def load_signer(tmp_path: Path, seed: bytes, name: str = "ledger.key") -> Any:
    return mods().signer.Ed25519FileSigner.load(write_key_file(tmp_path, seed, name))


def public_hex(seed: bytes) -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


def verifier_for(seed: bytes) -> Any:
    return mods().signer.Ed25519PublicVerifier.from_hex(public_hex(seed))


def ref_checkpoint(seed: bytes, chain_id: str, seq: int, head_hash: str, ts: datetime) -> Checkpoint:
    """Checkpoint signed by the REFERENCE message format and cryptography directly."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    msg = b"vulnscope-checkpoint-v1\n" + ref_canon(
        {"chain_id": chain_id, "seq": seq, "head_hash": head_hash, "ts": ref_ts(ts)}
    )
    sig = Ed25519PrivateKey.from_private_bytes(seed).sign(msg).hex()
    return Checkpoint(chain_id=chain_id, seq=seq, head_hash=head_hash, ts=ts, signature=sig)


def cp_over(entries: list[LedgerEntry], seq: int, seed: bytes = SEED1) -> Checkpoint:
    e = entries[seq]
    return ref_checkpoint(seed, e.chain_id, e.seq, e.record_hash, BASE_TS + timedelta(hours=1))


def flip_hex_char(s: str, index: int) -> str:
    c = s[index]
    return s[:index] + ("0" if c != "0" else "1") + s[index + 1:]


# ---------------------------------------------------------------- async + postgres helpers
def run(coro: Any) -> Any:
    return asyncio.run(coro)


def pg_scratch(request: pytest.FixtureRequest) -> Any:
    """The plugin's module-scope migrated scratch DB. Missing plugin = FAILURE, never a skip."""
    try:
        return request.getfixturevalue("migrated_scratch")
    except pytest.FixtureLookupError:
        pytest.fail(
            "Postgres variant needs `-p vulnscope_db_plugin` with PYTHONPATH including "
            "tests/stress/db (a skip would hide the missing proof)", pytrace=False,
        )


def pg_urls(db: Any) -> tuple[str, str, str]:
    """(app SQLAlchemy url, admin dsn, app dsn). Values are never printed or logged."""
    from stress_db_secrets import reveal

    return reveal(db.app_url), reveal(db.admin_dsn), reveal(db.app_dsn)


def pg_admin_sql(db: Any, *statements: str) -> None:
    import vulnscope_db_plugin as plug

    plug.execute(pg_urls(db)[1], *statements)


def pg_admin_fetch(db: Any, sql: str, *args: Any) -> list[Any]:
    import vulnscope_db_plugin as plug

    return plug.fetch(pg_urls(db)[1], sql, *args)


def sql_lit(s: str) -> str:
    """Single-quote a TEST-CONTROLLED literal (hex, ids, json we built ourselves)."""
    return "'" + s.replace("'", "''") + "'"


async def pg_backend(db: Any, **kwargs: Any) -> tuple[Any, Any]:
    from vulnscope.db.session import get_async_engine
    from vulnscope.ledger.postgres_backend import PostgresChainBackend

    engine = get_async_engine(pg_urls(db)[0])
    return engine, PostgresChainBackend(engine, **kwargs)
