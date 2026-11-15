"""Shared fixtures for API stress tests.

Recheck update (docs/gates/slice0-pre-stress-recheck.md): the ambiguity
originally flagged here (docs/gates/slice0-pre-stress.md) is resolved.
docs/gates/slice0-plan.md Section 3.7 (fixes STR-1) now PINS
`create_app(settings: Settings | None = None) -> FastAPI`, and this
fixture's zero-argument call matches it exactly (the `settings` parameter
is optional). Likewise `Org(id, name, ...)` / `ApiKey(id, org_id,
hashed_key, role, ...)` are pinned with additional nullable/defaulted
columns (`created_at`, `updated_at`, `revoked_at`) that do not affect the
keyword-argument construction used below. No fixture code changed as a
result -- only this comment, from "assumed" to "confirmed against §3.7".

All stress-test targets below are placeholder lab hostnames (*.lab.test);
per D8 the `lab` profile only exists when the deployment explicitly enables
it, so `_enable_lab_profile` sets that for the duration of each test. These
tests never make a real network connection themselves (pure API/DB
behaviour); they stay within "local labs on an isolated network" per
CLAUDE.md rule 2 by construction (no socket is ever opened here).
"""
from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

TEST_DATABASE_URL_ENV = "VULNSCOPE_TEST_DATABASE_URL"


@pytest.fixture
def test_database_url() -> str:
    url = os.environ.get(TEST_DATABASE_URL_ENV)
    if not url:
        pytest.skip(
            f"{TEST_DATABASE_URL_ENV} not set; API stress tests need a "
            "throwaway CI/dev Postgres instance wired through Task 0's "
            "db/session.py"
        )
    return url


@pytest.fixture(autouse=True)
def _enable_lab_profile(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VULNSCOPE_ENABLE_LAB", "1")
    monkeypatch.setenv("VULNSCOPE_LAB_CIDR", "127.0.0.1/32")


@pytest.fixture
def app():
    from vulnscope.api.main import create_app

    return create_app()


@pytest.fixture
def client(app) -> Iterator[TestClient]:
    with TestClient(app) as c:
        yield c


@pytest.fixture
def admin_api_key(app, test_database_url: str) -> str:
    """Seeds one Org + one admin ApiKey directly through the ORM (bypassing
    the API) and returns the raw bearer token.

    Field shapes are pinned by docs/gates/slice0-plan.md Section 3.7
    (fixes STR-1): `Org(id, name, ...)` / `ApiKey(id, org_id, hashed_key,
    role, ...)`, matching the construction below exactly. The extra
    columns §3.7 adds (`created_at`, `updated_at`, `revoked_at`) are
    nullable/defaulted and so are not passed here.
    """
    from vulnscope.api.auth import hash_api_key
    from vulnscope.db.session import get_sessionmaker
    from vulnscope.models.api_key import ApiKey
    from vulnscope.models.org import Org

    raw_key = f"vs_test_{uuid.uuid4().hex}"
    session_factory = get_sessionmaker(test_database_url)
    with session_factory() as session:
        org = Org(id=str(uuid.uuid4()), name=f"stress-org-{uuid.uuid4().hex[:8]}")
        session.add(org)
        session.flush()
        key_row = ApiKey(
            id=str(uuid.uuid4()),
            org_id=org.id,
            hashed_key=hash_api_key(raw_key),
            role="admin",
        )
        session.add(key_row)
        session.commit()

    return raw_key


@pytest.fixture
def engagement_payload_factory():
    """Returns a factory producing a payload shaped exactly like
    docs/io-contracts.md's engagement example, with a fresh,
    always-valid-at-call-time window."""

    def _make(name_suffix: str = "") -> dict:
        now = datetime.now(timezone.utc)
        not_before = now - timedelta(minutes=1)
        not_after = now + timedelta(days=7)
        return {
            "schema_version": 1,
            "name": f"stress-engagement-{uuid.uuid4().hex[:8]}{name_suffix}",
            "profile": "lab",
            "targets": {"domains": ["target.lab.test"], "ip_ranges": [], "openapi_url": None},
            "scope": {
                "allow": ["target.lab.test"],
                "deny": [],
                "expected_ip_ranges": [],
                "rate_limit_rps": 5,
                "window": {
                    "not_before": not_before.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "not_after": not_after.strftime("%Y-%m-%dT%H:%M:%SZ"),
                },
            },
            "authorization": {
                "confirmed": True,
                "statement": "Stress-test lab engagement, synthetic target only.",
                "approver": "stress-tester",
            },
            "identities": [],
            "ownership_rules": [],
            "asset_tags": [],
        }

    return _make
