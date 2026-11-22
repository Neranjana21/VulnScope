# ruff: noqa: E501
"""Postgres backend without a database: statement shapes, error sanitization (canary), the
per-chain gate invariants, privilege use. DB-backed behaviour is in tests/integration/ledger."""
from __future__ import annotations

import asyncio
import traceback
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import exc as sa_exc
from sqlalchemy.dialects import postgresql

from vulnscope.ledger import postgres_backend as pb
from vulnscope.ledger.canonical import prepare_append
from vulnscope.ledger.errors import LedgerStorageError
from vulnscope.ledger.postgres_backend import PostgresChainBackend

T0 = datetime(2026, 11, 19, tzinfo=UTC)
CID = "engagement:pgunit"
CANARY = "CANARY-PG-0123456789abcdef"


def sql(stmt: Any) -> str:
    return str(stmt.compile(dialect=postgresql.dialect()))


# ------------------------------------------------------------------ statement shapes
def test_lock_statement_is_select_for_update_on_chain_heads() -> None:
    s = sql(pb.stmt_lock_head(CID))
    assert "FROM chain_heads" in s and s.rstrip().endswith("FOR UPDATE")


def test_first_append_race_statement_is_insert_on_conflict_do_nothing() -> None:
    s = sql(pb.stmt_ensure_head(CID, "ab" * 32))
    assert s.startswith("INSERT INTO chain_heads") and "ON CONFLICT (chain_id) DO NOTHING" in s


def test_timeouts_are_transaction_local_set_config() -> None:
    s = sql(pb.stmt_set_timeouts())
    for name in ("lock_timeout", "statement_timeout", "idle_in_transaction_session_timeout"):
        assert f"set_config('{name}'" in s
    assert s.count(", true)") == 3  # is_local = true, i.e. SET LOCAL


def test_divergence_check_is_a_two_row_unique_index_lookup() -> None:
    s = sql(pb.stmt_tail_check(CID, 4))
    assert "FROM ledger_entries" in s and "ORDER BY ledger_entries.seq" in s and "LIMIT" in s


def test_the_only_dml_on_ledger_tables_is_insert_and_update_only_touches_chain_heads() -> None:
    p = prepare_append(CID, "evidence", "system", {"a": 1}, T0)
    statements = [
        sql(pb.stmt_insert_entry(p, 0, "ab" * 32, "cd" * 32)),
        sql(pb.stmt_insert_checkpoint(_cp())),
        sql(pb.stmt_update_head(CID, 0, "cd" * 32)),
        sql(pb.stmt_ensure_head(CID, "ab" * 32)),
    ]
    for s in statements:
        head = s.lstrip().split(None, 2)
        assert head[0] in ("INSERT", "UPDATE")
        if head[0] == "UPDATE":
            assert head[1] == "chain_heads"
    assert not any("DELETE" in s or "TRUNCATE" in s for s in statements)


def _cp() -> Any:
    from vulnscope.ledger.types import Checkpoint

    return Checkpoint(CID, 1, "ab" * 32, T0, "cd" * 64)


def test_reads_are_ordered_keyset_pages() -> None:
    s = sql(pb.stmt_read_batch(CID, 10, 500))
    assert "seq >=" in s and "ORDER BY ledger_entries.seq ASC" in s and "LIMIT" in s
    assert "ORDER BY ledger_entries.seq DESC" in sql(pb.stmt_head(CID))


# ------------------------------------------------------------------ error mapping
class _Driver(Exception):
    def __init__(self, sqlstate: str | None) -> None:
        super().__init__(f"driver says: INSERT ... [parameters: {CANARY}]")
        self.sqlstate = sqlstate
        self.detail = CANARY


@pytest.mark.parametrize(
    "state,code",
    [("55P03", "lock_timeout"), ("57014", "statement_timeout"), ("23505", "unique_violation"),
     ("42501", "insufficient_privilege"), ("P0001", "append_only_violation"),
     ("40001", "serialization"), ("40P01", "serialization"), ("08006", "connection"),
     ("08003", "connection"), ("22P02", "other"), (None, "other")],
)
def test_sqlstate_maps_to_a_fixed_code(state: str | None, code: str) -> None:
    exc = sa_exc.DBAPIError("SELECT 1", {"p": CANARY}, _Driver(state))
    err = pb._storage_error("append", exc)
    assert (err.code, err.sqlstate) == (code, state)
    assert CANARY not in str(err) and CANARY not in repr(err)
    assert err.__cause__ is None and err.__context__ is None


def test_pool_exhaustion_and_oserrors_have_their_own_codes() -> None:
    assert pb._storage_error("append", sa_exc.TimeoutError("pool")).code == "pool_timeout"
    assert pb._storage_error("read", ConnectionResetError("x")).code == "connection"
    assert pb._storage_error("head", ValueError(CANARY)).code == "other"


# ------------------------------------------------------------------ end to end without a database
class _ExplodingEngine:
    def connect(self) -> Any:
        raise sa_exc.DBAPIError(f"INSERT [parameters: ('{CANARY}',)]", {"payload": CANARY}, _Driver("23505"))


async def test_a_storage_failure_carries_no_payload_cause_or_context() -> None:
    b = PostgresChainBackend(_ExplodingEngine())  # type: ignore[arg-type]
    with pytest.raises(LedgerStorageError) as info:
        await b.append(CID, "policy.decision", "system", {"target": CANARY}, T0)
    err = info.value
    assert (err.operation, err.code, err.sqlstate) == ("append", "unique_violation", "23505")
    assert err.__cause__ is None and err.__context__ is None
    formatted = "".join(traceback.format_exception(err))
    assert CANARY not in formatted and CANARY not in repr(err) and CANARY not in str(err)
    assert b._gates == {}


async def test_validation_errors_raise_before_any_connection_is_made() -> None:
    from vulnscope.ledger.errors import CanonicalizationError

    class _Never:
        def connect(self) -> Any:
            raise AssertionError("connected")

    b = PostgresChainBackend(_Never())  # type: ignore[arg-type]
    with pytest.raises(CanonicalizationError):
        await b.append("bad id", "evidence", "system", {}, T0)
    with pytest.raises(CanonicalizationError):
        await b.append(CID, "evidence", "system", {}, datetime(2026, 1, 1))


class _Hang:
    def connect(self) -> Any:
        return self

    async def __aenter__(self) -> Any:
        await asyncio.Event().wait()

    async def __aexit__(self, *a: object) -> None:
        return None


async def test_gate_cancelled_waiters_leave_no_permits_or_map_entries() -> None:
    b = PostgresChainBackend(_Hang(), max_waiters_per_chain=2)  # type: ignore[arg-type]
    tasks = [asyncio.create_task(b.append(CID, "evidence", "system", {}, T0)) for _ in range(10)]
    await asyncio.sleep(0.05)
    gate = b._gates[CID]
    assert gate.refs == 10  # 2 inside the semaphore, 8 queued without a connection
    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    assert b._gates == {}  # entry removed in a finally, also on cancellation
    b2 = PostgresChainBackend(_ExplodingEngine(), max_waiters_per_chain=1)  # type: ignore[arg-type]
    with pytest.raises(LedgerStorageError):
        await b2.append(CID, "evidence", "system", {}, T0)  # the permit was released


async def test_chain_id_spray_leaves_an_empty_gate_map() -> None:
    b = PostgresChainBackend(_ExplodingEngine())  # type: ignore[arg-type]
    for i in range(300):
        with pytest.raises(LedgerStorageError):
            await b.append(f"intake:spray{i}", "evidence", "system", {}, T0)
    assert b._gates == {}


async def test_at_most_n_writers_per_chain_reach_the_pool() -> None:
    inside = {"now": 0, "max": 0}

    class _Count:
        def connect(self) -> Any:
            return self

        async def __aenter__(self) -> Any:
            inside["now"] += 1
            inside["max"] = max(inside["max"], inside["now"])
            try:
                await asyncio.sleep(0.01)
                raise sa_exc.OperationalError("x", None, _Driver("08006"))
            finally:
                inside["now"] -= 1

        async def __aexit__(self, *a: object) -> None:
            return None

    b = PostgresChainBackend(_Count(), max_waiters_per_chain=3)  # type: ignore[arg-type]
    res = await asyncio.gather(
        *(b.append(CID, "evidence", "system", {}, T0) for _ in range(20)), return_exceptions=True
    )
    assert all(isinstance(r, LedgerStorageError) for r in res)
    assert inside["max"] <= 3


def test_constructor_rejects_non_positive_limits() -> None:
    for kw in ({"lock_timeout_ms": 0}, {"read_batch": -1}, {"max_waiters_per_chain": 0}):
        with pytest.raises(ValueError):
            PostgresChainBackend(None, **kw)  # type: ignore[arg-type]
