"""Size, count and time limits for the API (module constants because ``config.py`` is frozen;
``Timeouts`` carries the timing ones so tests can inject small values without touching module
constants). Design: PD-04, PD-05, PD-08, PD-10, PD-15, PD-24, N-02, N-03."""
from __future__ import annotations

from dataclasses import dataclass

# Request bodies (bytes)
MAX_BODY_BYTES = 262_144  # global ceiling, also the pre-auth declared-length cap
BODY_CAP_ENGAGEMENT = 262_144
BODY_CAP_SCAN = 16_384
BODY_CAP_REVOKE = 4_096

# Hostile-JSON bounds (bodies.py)
MAX_BRACKETS = 1024
MAX_INT_LITERAL = 18
MAX_FLOAT_LITERAL = 32
MAX_OBJECT_KEYS = 512
MAX_DEPTH = 12
MAX_NODES = 20_000
MAX_STRING_CHARS = 8_192
MAX_PYDANTIC_ERRORS_INSPECTED = 64

# Field limits (phase L)
NAME_MAX = 255
APPROVER_MAX = 200
STATEMENT_MAX = 4_096
REASON_MAX = 1_024
SCOPE_LIST_MAX = 256
SCOPE_ENTRY_MAX = 253
MAX_TARGETS = 50
OPENAPI_URL_MAX = 2_048
IDENTITIES_MAX = 16
OWNERSHIP_RULES_MAX = 64
ASSET_TAGS_MAX = 64
LABEL_MAX = 64
SECRET_REF_MAX = 256
RESOURCE_MAX = 512
CRITICALITY_MAX = 32
MAX_STAGES = 4

# Idempotency
MAX_KEY_LEN = 255
IDEMPOTENCY_TTL_S = 24 * 3600

# Revoke recorder
MAX_CHAIN_SCAN = 20_000
MAX_RECONCILE_ROWS = 1_000
RECONCILE_BATCH = 200
RECONCILE_DAYS = 7

# Chain ids / path ids
MAX_ID_LEN = 64
MAX_CHAIN_PARAM_LEN = 100

MEDIA_TYPE_PROBLEM = "application/problem+json"


@dataclass(frozen=True)
class Timeouts:
    request_deadline_s: float = 30.0
    # AuthGate (PD-10, N-03): shared slots plus slots reserved for the revoke route
    auth_inflight: int = 6
    auth_reserved: int = 2
    auth_queue_wait_s: float = 1.0
    auth_db_budget_s: float = 2.0
    db_op_budget_s: float = 5.0
    # Idempotency claims
    claim_wait_s: float = 10.0
    claim_poll_s: float = 0.05
    claim_stale_s: float = 60.0
    revoke_claim_stale_s: float = 120.0
    # Scan creation (PD-08, N-06)
    scan_deadline_s: float = 15.0
    scan_inflight_global: int = 4
    scan_inflight_per_org: int = 2
    admission_wait_s: float = 2.0
    resolve_timeout_s: float = 2.0
    # Verify (PD-15)
    verify_inflight_global: int = 2
    verify_max_records: int = 50_000
    verify_deadline_s: float = 10.0
    # DB (PD-24)
    lock_timeout_ms: int = 2_000
    statement_timeout_ms: int = 5_000
    # Revoke recorder (N-02)
    max_chain_scan: int = MAX_CHAIN_SCAN
    revoke_search_budget_s: float = 10.0
