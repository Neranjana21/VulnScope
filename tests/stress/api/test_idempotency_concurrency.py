"""Stress: idempotency under concurrency. N simultaneous POSTs with the
same Idempotency-Key must create exactly one resource, not N.

Catalogue row: docs/stress-tests.md "API" -> "Idempotency: replayed POST
/scans with the same key creates one engagement." S0's concrete POST-that-
creates-a-resource endpoint sharing api/idempotency.py's dependency is
POST /v1/engagements (docs/gates/slice0-plan.md api/idempotency.py); this
file stress-tests that endpoint under real concurrency, which is the
generalization the task brief asks for ("N simultaneous requests ... same
Idempotency-Key ... exactly one created resource").
Supports: Slice 0 AC6 ("idempotency behaves as specified").

Needs a throwaway Postgres instance (VULNSCOPE_TEST_DATABASE_URL) and
Task D's FastAPI app; skipped otherwise (see tests/stress/api/conftest.py).

Async update (docs/gates/slice0-pre-stress-recheck.md round 3): the
`admin_api_key` fixture is now an async fixture (per
docs/gates/slice0-plan.md §3.7/§3.8); both test functions below are `async
def` only so pytest-asyncio can resolve it -- their bodies stay fully
synchronous (`TestClient`, `ThreadPoolExecutor`).
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

pytestmark = pytest.mark.requires_postgres

N_CONCURRENT = 30


@pytest.mark.asyncio
async def test_same_key_same_body_concurrent_creates_exactly_one_resource(
    client: TestClient, admin_api_key: str, engagement_payload_factory
) -> None:
    payload = engagement_payload_factory()
    key = payload["name"]  # any fixed string; reused across all N requests

    def do_post(_: int):
        return client.post(
            "/v1/engagements",
            json=payload,
            headers={"Authorization": f"Bearer {admin_api_key}", "Idempotency-Key": key},
        )

    with ThreadPoolExecutor(max_workers=N_CONCURRENT) as pool:
        responses = list(pool.map(do_post, range(N_CONCURRENT)))

    statuses = [r.status_code for r in responses]
    assert all(s == 201 for s in statuses), f"unexpected statuses: {statuses}"

    ids = {r.json()["id"] for r in responses}
    assert len(ids) == 1, (
        f"{len(ids)} distinct engagement ids were created from {N_CONCURRENT} "
        f"concurrent requests sharing one Idempotency-Key: {ids}"
    )


@pytest.mark.asyncio
async def test_same_key_different_body_concurrent_conflicts_not_duplicates(
    client: TestClient, admin_api_key: str, engagement_payload_factory
) -> None:
    key = "stress-idempotency-conflict-key"

    def do_post(i: int):
        payload = engagement_payload_factory(name_suffix=f"-variant-{i}")
        return client.post(
            "/v1/engagements",
            json=payload,
            headers={"Authorization": f"Bearer {admin_api_key}", "Idempotency-Key": key},
        )

    with ThreadPoolExecutor(max_workers=N_CONCURRENT) as pool:
        responses = list(pool.map(do_post, range(N_CONCURRENT)))

    statuses = [r.status_code for r in responses]
    created = [r for r in responses if r.status_code == 201]
    conflicted = [r for r in responses if r.status_code == 409]

    assert len(created) == 1, (
        f"expected exactly one 201 among {N_CONCURRENT} concurrent requests "
        f"sharing one Idempotency-Key with different bodies; got statuses={statuses}"
    )
    assert len(conflicted) == N_CONCURRENT - 1
    for resp in conflicted:
        body = resp.json()
        assert body.get("code") == "IDEMPOTENCY_CONFLICT"
