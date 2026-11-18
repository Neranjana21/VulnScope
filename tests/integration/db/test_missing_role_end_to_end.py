"""L6b (docs/gates/slice0-plan.md 3.10.1): when the application role does not exist,
``alembic upgrade head`` fails cleanly before any DDL, through the default path.

There is no command-line, environment or config seam for the role name (GR-SEC-1); the only
seam is the in-process module attribute ``migration_grants.APP_ROLE``, which this test
monkeypatches and which no CLI can reach. The real default-role case (``vulnscope_app``
actually dropped) is proven once by dry-run step G7, not here, because that role is
cluster-global.

A synchronous test: ``alembic/env.py`` calls ``asyncio.run`` and must not run inside pytest's
event loop. Assertions are over plain values only (no DSN, URL or fixture object).
"""
from __future__ import annotations

import secrets
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config

_INTEGRATION_DIR = Path(__file__).resolve().parents[1]
if str(_INTEGRATION_DIR) not in sys.path:
    sys.path.insert(0, str(_INTEGRATION_DIR))

from _dbkit import REPO_ROOT, kit  # noqa: E402


@pytest.mark.integration
def test_upgrade_without_app_role_fails_cleanly(
    scratch_db_factory: Callable[..., Any], stress_env: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    k = kit()
    mg = k.lazy("vulnscope.db.migration_grants")
    db = scratch_db_factory(migrate=False)
    missing = f"vtest_missing_{secrets.token_hex(4)}"
    monkeypatch.setattr(mg, "APP_ROLE", missing)
    monkeypatch.setenv("VULNSCOPE_MIGRATION_DATABASE_URL", db.admin_url)
    cfg = Config(str(REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(REPO_ROOT / "alembic"))

    with pytest.raises(mg.MigrationPreconditionError) as raised:
        command.upgrade(cfg, "head")
    message = str(raised.value)

    assert "not in pg_roles" in message
    assert missing in message
    tables = [t for t in k.user_tables(db) if t != "public.alembic_version"]
    assert tables == [], f"tables exist after the refused migration: {tables}"
    if "public.alembic_version" in k.user_tables(db):
        rows = k.fetchval(db.admin_dsn, "SELECT count(*) FROM public.alembic_version")
        assert rows == 0, "alembic_version has a row after the refused migration"
