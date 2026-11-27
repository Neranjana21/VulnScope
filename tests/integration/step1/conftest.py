"""Step 1 integration fixtures. These run ONLY against a disposable per-task database
created by ``scripts/with_task_db.py --mode task`` (never the shared dev ledger)."""

from __future__ import annotations

import os
import re
import sys
from collections.abc import AsyncIterator
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

_ROOT = str(Path(__file__).resolve().parents[3])
if _ROOT not in sys.path:
    sys.path.append(_ROOT)
_FAKES = str(Path(__file__).resolve().parents[2] / "unit" / "devpath")
if _FAKES not in sys.path:
    sys.path.append(_FAKES)  # lab_fake: the test-owned port 3000 listener and safety net

from vulnscope.config import Settings  # noqa: E402
from vulnscope.db.session import get_async_engine  # noqa: E402

_TASK_DB = re.compile(r"vulnscope_task[a-z]_[0-9a-f]{8}")


@pytest.fixture
def settings() -> Settings:
    """Skips only when no database was configured; anything else wrong is a failure.
    Messages never include the URL."""
    url = os.environ.get("VULNSCOPE_DATABASE_URL")
    if not url:
        pytest.skip("no task database configured (run through scripts/with_task_db.py)")
    parts = urlsplit(url)
    safe = (
        parts.hostname == "127.0.0.1"
        and parts.port == 5432
        and _TASK_DB.fullmatch(parts.path.lstrip("/")) is not None
        and not parts.query
    )
    if not safe:
        pytest.fail("the configured database is not a disposable task database", pytrace=False)
    loaded = Settings()
    if not loaded.enable_lab:
        pytest.fail("VULNSCOPE_ENABLE_LAB=1 must be set in the child command", pytrace=False)
    return loaded


@pytest.fixture
async def engine(settings: Settings) -> AsyncIterator[AsyncEngine]:
    assert settings.database_url is not None
    built = get_async_engine(settings.database_url)
    try:
        yield built
    finally:
        await built.dispose()
