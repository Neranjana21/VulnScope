"""DE-04: the shipped defaults are part of the safety design; changing one must fail a test."""
from __future__ import annotations

from dataclasses import asdict

from vulnscope.api.limits import Timeouts
from vulnscope.config import MAX_AUTH_SLOTS_TOTAL

EXPECTED = {
    "request_deadline_s": 30.0,
    "auth_inflight": 8,
    "auth_reserved": 2,
    "auth_queue_wait_s": 3.0,
    "auth_db_budget_s": 3.0,
    "db_op_budget_s": 5.0,
    "claim_wait_s": 10.0,
    "claim_poll_s": 0.05,
    "claim_stale_s": 60.0,
    "revoke_claim_stale_s": 120.0,
    "scan_deadline_s": 15.0,
    "scan_inflight_global": 4,
    "scan_inflight_per_org": 2,
    "admission_wait_s": 2.0,
    "resolve_timeout_s": 2.0,
    "verify_inflight_global": 2,
    "verify_max_records": 50_000,
    "verify_deadline_s": 10.0,
    "lock_timeout_ms": 2_000,
    "statement_timeout_ms": 5_000,
    "max_chain_scan": 20_000,
    "revoke_search_budget_s": 10.0,
}


def test_defaults_are_pinned() -> None:
    assert asdict(Timeouts()) == EXPECTED


def test_defaults_obey_their_own_documented_relations() -> None:
    t = Timeouts()
    assert t.auth_reserved >= 1  # revoke must stay reachable during a flood (N-03)
    assert t.auth_inflight + t.auth_reserved <= MAX_AUTH_SLOTS_TOTAL
    assert t.auth_queue_wait_s < t.request_deadline_s
    assert t.auth_db_budget_s <= t.db_op_budget_s
    assert t.scan_inflight_per_org <= t.scan_inflight_global
    assert t.lock_timeout_ms < t.statement_timeout_ms
