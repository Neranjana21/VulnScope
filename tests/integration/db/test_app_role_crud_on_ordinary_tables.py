# ruff: noqa: E501
"""L2 (docs/gates/slice0-plan.md 3.10.1): as ``vulnscope_app`` on the shared dev database,
ordinary tables (``orgs``, ``idempotency_keys``) allow SELECT/INSERT/UPDATE/DELETE, while DDL
(``CREATE TABLE``, ``ALTER TABLE``) is refused with ``InsufficientPrivilegeError``.

Every statement runs inside a transaction that is always rolled back, so no row or object is
ever left behind; the shared-database advisory lock keeps concurrent sessions apart. Assertions
are written over plain values only (pytest prints failed-assertion operands; no DSN or URL may
reach them).
"""
from __future__ import annotations

import sys
import uuid
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import pytest
from asyncpg.exceptions import InsufficientPrivilegeError

_INTEGRATION_DIR = Path(__file__).resolve().parents[1]
if str(_INTEGRATION_DIR) not in sys.path:
    sys.path.insert(0, str(_INTEGRATION_DIR))

from _dbkit import kit  # noqa: E402


def _in_rolled_back_txn(
    stress_env: Any, work: Callable[[Any], Awaitable[Any]]
) -> Any:
    """Run ``work(conn)`` as the app role in a transaction that is always rolled back."""
    k = kit()

    async def _go(conn: Any) -> Any:
        who = await conn.fetchrow(
            "SELECT current_user::text AS u, rolsuper FROM pg_roles WHERE rolname = current_user"
        )
        if who["u"] != "vulnscope_app" or who["rolsuper"]:
            raise AssertionError("connected as the wrong role; expected the non-superuser vulnscope_app")
        tr = conn.transaction()
        await tr.start()
        try:
            return await work(conn)
        finally:
            await tr.rollback()

    return k.with_conn(k.to_dsn(stress_env.app_url), _go)


@pytest.mark.integration
def test_app_role_crud_on_ordinary_tables(stress_env: Any, shared_db_lock: None) -> None:
    org_id = str(uuid.uuid4())
    key = f"l2-{uuid.uuid4()}"

    async def work(conn: Any) -> dict[str, Any]:
        out: dict[str, Any] = {}
        await conn.execute(
            "INSERT INTO orgs (id, name, created_at, updated_at) VALUES ($1, 'l2', now(), now())", org_id
        )
        out["orgs_select"] = await conn.fetchval("SELECT count(*) FROM orgs WHERE id = $1", org_id)
        out["orgs_update"] = await conn.execute("UPDATE orgs SET name = 'l2b' WHERE id = $1", org_id)
        out["orgs_delete"] = await conn.execute("DELETE FROM orgs WHERE id = $1", org_id)

        await conn.execute(
            "INSERT INTO idempotency_keys (key, org_id, request_hash, response_body, response_status, "
            "created_at) VALUES ($1, $2, repeat('0', 64), '{}'::json, 200, now())",
            key, org_id,
        )
        out["idem_select"] = await conn.fetchval("SELECT count(*) FROM idempotency_keys WHERE key = $1", key)
        out["idem_update"] = await conn.execute(
            "UPDATE idempotency_keys SET response_status = 201 WHERE key = $1", key
        )
        out["idem_delete"] = await conn.execute("DELETE FROM idempotency_keys WHERE key = $1", key)
        return out

    out = _in_rolled_back_txn(stress_env, work)

    assert out["orgs_select"] == 1
    assert out["orgs_update"] == "UPDATE 1"
    assert out["orgs_delete"] == "DELETE 1"
    assert out["idem_select"] == 1
    assert out["idem_update"] == "UPDATE 1"
    assert out["idem_delete"] == "DELETE 1"


@pytest.mark.integration
def test_app_role_cannot_create_or_alter_tables(stress_env: Any, shared_db_lock: None) -> None:
    for statement in (
        "CREATE TABLE public.vulnscope_l2_scratch (id integer)",
        "ALTER TABLE orgs ADD COLUMN l2_scratch integer",
    ):

        async def work(conn: Any, statement: str = statement) -> None:
            await conn.execute(statement)

        with pytest.raises(InsufficientPrivilegeError):
            _in_rolled_back_txn(stress_env, work)
