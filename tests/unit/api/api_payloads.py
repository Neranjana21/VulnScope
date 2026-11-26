"""Engagement / scan payload builders shared by the API tests (same shape as the R1 factory)."""
from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

FMT = "%Y-%m-%dT%H:%M:%SZ"


def valid_payload(now: datetime | None = None, *, suffix: str = "") -> dict[str, Any]:
    now = now or datetime.now(UTC)
    return {
        "schema_version": 1,
        "name": f"it-engagement-{uuid.uuid4().hex[:8]}{suffix}",
        "profile": "lab",
        "targets": {"domains": ["target.lab.test"], "ip_ranges": [], "openapi_url": None},
        "scope": {
            "allow": ["target.lab.test"],
            "deny": [],
            "expected_ip_ranges": [],
            "rate_limit_rps": 5,
            "window": {
                "not_before": (now - timedelta(minutes=1)).strftime(FMT),
                "not_after": (now + timedelta(days=7)).strftime(FMT),
            },
        },
        "authorization": {
            "confirmed": True,
            "statement": "Integration-test lab engagement, synthetic target only.",
            "approver": "it-tester",
        },
        "identities": [],
        "ownership_rules": [],
        "asset_tags": [],
    }


def mutated(mutator: Callable[[dict[str, Any]], None],
            now: datetime | None = None) -> dict[str, Any]:
    q = valid_payload(now)
    mutator(q)
    return q


SCAN_PAYLOAD: dict[str, Any] = {
    "schema_version": 1,
    "stages": ["discover", "detect", "validate", "path"],
    "options": {"write_tests": False},
    "schedule": None,
}
