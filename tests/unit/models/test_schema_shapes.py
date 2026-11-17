"""Every Pydantic schema round-trips the exact example payloads shown in
docs/io-contracts.md (engagement create, scan create, policy decision,
ledger entry, finding, evidence); unknown fields are rejected
(``UNKNOWN_FIELD``). docs/gates/slice0-plan.md Section 5, Task 0.
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from vulnscope.models.schemas.engagement import EngagementCreateRequest
from vulnscope.models.schemas.finding import EvidenceView, FindingView
from vulnscope.models.schemas.ledger import LedgerEntryView
from vulnscope.models.schemas.policy import PolicyDecisionView
from vulnscope.models.schemas.scan import ScanCreateRequest

# --- docs/io-contracts.md "Engagement": POST /v1/engagements example ---
ENGAGEMENT_CREATE_PAYLOAD = {
    "schema_version": 1,
    "name": "juice-shop-pentest",
    "profile": "lab",
    "targets": {"domains": ["juice.lab.test"], "ip_ranges": [], "openapi_url": None},
    "scope": {
        "allow": ["juice.lab.test"],
        "deny": [],
        "expected_ip_ranges": [],
        "rate_limit_rps": 5,
        "window": {
            "not_before": "2026-01-01T00:00:00Z",
            "not_after": "2026-01-31T00:00:00Z",
        },
    },
    "authorization": {
        "confirmed": True,
        "statement": "Operator-authorized lab pentest.",
        "approver": "owner",
    },
    "identities": [
        {
            "label": "user_a",
            "role": "citizen",
            "auth": {"type": "bearer", "secret_ref": "ref://engagements/e1/user_a"},
        }
    ],
    "ownership_rules": [{"resource": "/records/{id}", "owner_identity": "user_a"}],
    "asset_tags": [{"match": "juice.lab.test", "criticality": "high", "data": "personal"}],
}

# --- docs/io-contracts.md "Scan": POST /v1/engagements/{id}/scans example ---
SCAN_CREATE_PAYLOAD = {
    "schema_version": 1,
    "stages": ["discover", "detect", "validate", "path"],
    "options": {"write_tests": False},
    "schedule": None,
}

# --- docs/io-contracts.md "Policy decision" example ---
POLICY_DECISION_PAYLOAD = {
    "allowed": False,
    "reason": "target matches the always-deny list",
    "rule_id": "DENY_ALWAYS_LIST",
    "policy_version": "1.0.0+abcdef0",
    "action": {
        "kind": "http",
        "target": "169.254.169.254",
        "resolved_ips": ["169.254.169.254"],
        "adapter": "fake",
    },
    "ts": "2026-01-02T03:04:05Z",
}

# --- docs/io-contracts.md "Ledger entry" example ---
LEDGER_ENTRY_PAYLOAD = {
    "schema_version": 1,
    "chain_id": "engagement:e1",
    "seq": 0,
    "kind": "policy.decision",
    "actor": "system",
    "payload": {"allowed": True},
    "ts": "2026-01-02T03:04:05Z",
    "prev_hash": "a" * 64,
    "record_hash": "b" * 64,
}

# --- docs/io-contracts.md "Finding" example ---
FINDING_PAYLOAD = {
    "id": "0190aaaa-bbbb-7ccc-8ddd-eeeeeeeeeeee",
    "schema_version": 1,
    "org_id": "0190aaaa-bbbb-7ccc-8ddd-eeeeeeeeeeef",
    "engagement_id": "0190aaaa-bbbb-7ccc-8ddd-eeeeeeeeeeff",
    "asset_id": "0190aaaa-bbbb-7ccc-8ddd-eeeeeeeeefff",
    "title": "Reflected XSS on /search",
    "cwe": "CWE-79",
    "taxonomy": ["xss"],
    "owasp_api": None,
    "status": "candidate",
    "severity": "medium",
    "evidence_ids": [],
    "cvss": {
        "version": "4.0",
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
        "score": 5.1,
        "source": "fixture",
        "snapshot": "2026-01-01",
    },
    "priority": {
        "band": "medium",
        "reasons": ["reachable from the internet"],
        "policy_version": "1.0.0+abcdef0",
        "unknown_inputs": [],
    },
    "source_adapter": {"name": "fake", "version": "0.1.0"},
    "first_seen": "2026-01-02T03:04:05Z",
    "last_seen": "2026-01-02T03:04:05Z",
}

# --- docs/io-contracts.md "Evidence record" example ---
EVIDENCE_PAYLOAD = {
    "id": "0190aaaa-bbbb-7ccc-8ddd-eeeeeeeeefaa",
    "finding_id": "0190aaaa-bbbb-7ccc-8ddd-eeeeeeeeeeee",
    "kind": "http_response_excerpt",
    "redacted_excerpt": "<script>***redacted***</script>",
    "content_sha256": "c" * 64,
    "identity_label": "user_a",
    "expected": "200 with sanitized input reflected",
    "observed": "200 with raw input reflected",
    "policy_version": "1.0.0+abcdef0",
    "adapter": {"name": "fake", "version": "0.1.0"},
    "ledger_chain": "engagement:e1",
    "ledger_seq": 3,
    "created_at": "2026-01-02T03:04:05Z",
}


@pytest.mark.parametrize(
    ("schema_cls", "payload"),
    [
        (EngagementCreateRequest, ENGAGEMENT_CREATE_PAYLOAD),
        (ScanCreateRequest, SCAN_CREATE_PAYLOAD),
        (PolicyDecisionView, POLICY_DECISION_PAYLOAD),
        (LedgerEntryView, LEDGER_ENTRY_PAYLOAD),
        (FindingView, FINDING_PAYLOAD),
        (EvidenceView, EVIDENCE_PAYLOAD),
    ],
)
def test_schema_round_trips_example_payload(schema_cls, payload: dict) -> None:
    model = schema_cls.model_validate(payload)
    # Round-trip: dumping back to JSON-compatible mode and re-validating
    # must reproduce an equivalent object (no silent field loss/mutation).
    dumped = model.model_dump(mode="json")
    model_again = schema_cls.model_validate(dumped)
    assert model_again == model


@pytest.mark.parametrize(
    ("schema_cls", "payload"),
    [
        (EngagementCreateRequest, ENGAGEMENT_CREATE_PAYLOAD),
        (ScanCreateRequest, SCAN_CREATE_PAYLOAD),
        (PolicyDecisionView, POLICY_DECISION_PAYLOAD),
        (LedgerEntryView, LEDGER_ENTRY_PAYLOAD),
        (FindingView, FINDING_PAYLOAD),
        (EvidenceView, EVIDENCE_PAYLOAD),
    ],
)
def test_schema_rejects_unknown_field(schema_cls, payload: dict) -> None:
    with pytest.raises(ValidationError):
        schema_cls.model_validate({**payload, "totally_unexpected_field": "x"})


def test_window_naive_datetime_rejected() -> None:
    payload = {
        **ENGAGEMENT_CREATE_PAYLOAD,
        "scope": {
            **ENGAGEMENT_CREATE_PAYLOAD["scope"],
            "window": {"not_before": "2026-01-01T00:00:00", "not_after": "2026-01-31T00:00:00"},
        },
    }
    with pytest.raises(ValidationError):
        EngagementCreateRequest.model_validate(payload)


def test_engagement_secret_ref_pattern_enforced() -> None:
    bad_payload = {
        **ENGAGEMENT_CREATE_PAYLOAD,
        "identities": [
            {
                "label": "user_a",
                "role": "citizen",
                "auth": {"type": "bearer", "secret_ref": "not-a-ref"},
            }
        ],
    }
    with pytest.raises(ValidationError):
        EngagementCreateRequest.model_validate(bad_payload)
