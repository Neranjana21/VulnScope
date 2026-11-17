"""Stress: sustained + burst load against non-scan API endpoints; p95
latency and error rate recorded (R6: non-scan API p95 < 200ms).

Catalogue row: docs/stress-tests.md "API" -> "Load: sustained and burst
request rates; p95 latency and error rate recorded."
Supports: Slice 0 AC6 (engagement creation path), AC8/AC9 indirectly
(auth + ledger surfaced through the same endpoints under load).

Needs a throwaway Postgres instance (VULNSCOPE_TEST_DATABASE_URL) and
Task D's FastAPI app; skipped otherwise (see tests/stress/api/conftest.py).

Async update (docs/gates/slice0-pre-stress-recheck.md round 3): the
`admin_api_key` fixture is now an async fixture (it seeds rows via
`get_async_sessionmaker()`, per docs/gates/slice0-plan.md §3.7/§3.8). Any
test consuming it must itself be `async def` for pytest-asyncio to resolve
it -- this is the only reason the three test functions below are `async
def` now; their BODIES remain fully synchronous (plain `TestClient` calls,
`ThreadPoolExecutor`), since neither `app`/`client` nor these tests touch
`ChainBackend`/`PostgresChainBackend` directly (see the conftest module
docstring for why those two fixtures are unaffected).
"""
from __future__ import annotations

import statistics
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

pytestmark = pytest.mark.requires_postgres

P95_BUDGET_SECONDS = 0.200  # R6: non-scan API p95 < 200ms
CI_SLACK_MULTIPLIER = 5  # generous slack for shared/virtualised CI hardware;
# record the MEASURED number in the post-gate regardless of pass/fail.


def _percentile(values: list[float], p: float) -> float:
    ordered = sorted(values)
    idx = max(0, int(len(ordered) * p) - 1)
    return ordered[idx]


def _timed_create(client: TestClient, api_key: str, payload_factory) -> tuple[float, int]:
    payload = payload_factory()
    start = time.perf_counter()
    resp = client.post(
        "/v1/engagements",
        json=payload,
        headers={"Authorization": f"Bearer {api_key}", "Idempotency-Key": payload["name"]},
    )
    elapsed = time.perf_counter() - start
    return elapsed, resp.status_code


@pytest.mark.asyncio
async def test_sustained_load_engagement_creation(
    client: TestClient, admin_api_key: str, engagement_payload_factory
) -> None:
    n_requests = 100
    latencies: list[float] = []
    statuses: list[int] = []

    for _ in range(n_requests):
        elapsed, status = _timed_create(client, admin_api_key, engagement_payload_factory)
        latencies.append(elapsed)
        statuses.append(status)
        time.sleep(0.01)  # ~sustained, well under a burst

    error_rate = sum(1 for s in statuses if s >= 500) / n_requests
    p50 = statistics.median(latencies)
    p95 = _percentile(latencies, 0.95)
    p99 = _percentile(latencies, 0.99)
    print(
        f"sustained POST /v1/engagements: n={n_requests} p50={p50 * 1000:.1f}ms "
        f"p95={p95 * 1000:.1f}ms p99={p99 * 1000:.1f}ms server_error_rate={error_rate:.2%}"
    )

    assert error_rate == 0.0, f"{error_rate:.2%} of sustained requests returned 5xx"
    budget = P95_BUDGET_SECONDS * CI_SLACK_MULTIPLIER
    assert p95 < budget, (
        f"p95={p95 * 1000:.1f}ms exceeds the CI-adjusted budget {budget * 1000:.0f}ms "
        f"(R6 target: {P95_BUDGET_SECONDS * 1000:.0f}ms)"
    )


@pytest.mark.asyncio
async def test_burst_load_engagement_creation(
    client: TestClient, admin_api_key: str, engagement_payload_factory
) -> None:
    n_requests = 50
    with ThreadPoolExecutor(max_workers=25) as pool:
        results = list(
            pool.map(
                lambda _: _timed_create(client, admin_api_key, engagement_payload_factory),
                range(n_requests),
            )
        )

    latencies = [r[0] for r in results]
    statuses = [r[1] for r in results]
    error_rate = sum(1 for s in statuses if s >= 500) / n_requests
    p95 = _percentile(latencies, 0.95)

    print(
        f"burst POST /v1/engagements: n={n_requests} concurrency=25 "
        f"p95={p95 * 1000:.1f}ms server_error_rate={error_rate:.2%} statuses={sorted(set(statuses))}"
    )
    assert error_rate == 0.0, f"{error_rate:.2%} of burst requests returned 5xx"


@pytest.mark.asyncio
async def test_sustained_load_ledger_verify(client: TestClient, admin_api_key: str) -> None:
    n_requests = 100
    latencies: list[float] = []
    statuses: list[int] = []
    chain_id = f"intake:{uuid.uuid4()}"

    for _ in range(n_requests):
        start = time.perf_counter()
        resp = client.get(
            "/v1/ledger/verify",
            params={"chain": chain_id},
            headers={"Authorization": f"Bearer {admin_api_key}"},
        )
        latencies.append(time.perf_counter() - start)
        statuses.append(resp.status_code)
        time.sleep(0.01)

    error_rate = sum(1 for s in statuses if s >= 500) / n_requests
    p95 = _percentile(latencies, 0.95)
    print(
        f"sustained GET /v1/ledger/verify: n={n_requests} p95={p95 * 1000:.1f}ms "
        f"error_rate={error_rate:.2%}"
    )

    assert error_rate == 0.0
    assert p95 < P95_BUDGET_SECONDS * CI_SLACK_MULTIPLIER
