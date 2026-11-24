"""Ledger payload builders and the class-agnostic append wrapper (PD-05, B-R1-3, design 3).

Every builder ends with the injected ``sanitize`` (rule 6). Payloads hold only str, int, bool and
lists/dicts of those (no floats), record the authorization block under ``authorization_basis``
(never ``authorization``: the ledger redaction blocklist is exact-key), and carry hashes and lengths
instead of free text. A failed append is always a visible 503, never swallowed.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any

from vulnscope.api.logging import log_event
from vulnscope.api.ports import Sanitizer
from vulnscope.api.problem import Detail, ProblemError
from vulnscope.api.state import AppState
from vulnscope.errors import ReasonCode
from vulnscope.ledger.types import LedgerEntry
from vulnscope.models.schemas.engagement import EngagementCreateRequest

SCHEMA = 1


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_json(value: Any) -> str:
    return sha256_text(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True))


def engagement_created(sanitize: Sanitizer, *, engagement_id: str,
                       req: EngagementCreateRequest) -> dict[str, object]:
    a = req.authorization
    payload: dict[str, object] = {
        "schema_version": SCHEMA,
        "engagement_id": engagement_id,
        "profile": req.profile,
        "authorization_basis": {
            "confirmed": a.confirmed,
            "approver_sha256": sha256_text(a.approver), "approver_len": len(a.approver),
            "statement_sha256": sha256_text(a.statement), "statement_len": len(a.statement),
        },
        "scope_sha256": sha256_json(req.scope.model_dump(mode="json")),
        "window_not_before": req.scope.window.not_before.isoformat(),
        "window_not_after": req.scope.window.not_after.isoformat(),
        "rate_limit_mrps": int(round(req.scope.rate_limit_rps * 1000)),
    }
    return sanitize(payload)


def engagement_rejected(sanitize: Sanitizer, *, codes: Sequence[str], paths: Sequence[str],
                        unknown_field_count: int = 0) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": SCHEMA, "codes": list(codes), "primary": codes[0], "paths": list(paths)}
    if unknown_field_count:
        payload["unknown_field_count"] = unknown_field_count
    return sanitize(payload)


def engagement_revoked(sanitize: Sanitizer, *, engagement_id: str, revoked_at: datetime,
                       reason: str, revoked_by: str, repaired: bool) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": SCHEMA, "engagement_id": engagement_id,
        "revoked_at": revoked_at.isoformat(), "reason_sha256": sha256_text(reason),
        "reason_len": len(reason), "revoked_by": revoked_by, "repaired": repaired}
    return sanitize(payload)


def scan_created(sanitize: Sanitizer, *, scan_id: str, engagement_id: str,
                 stages: Sequence[str], decision_count: int,
                 range_checks: Sequence[Mapping[str, object]],
                 lifecycle_probe: bool) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": SCHEMA, "scan_id": scan_id, "engagement_id": engagement_id,
        "stages": list(stages), "write_tests": False, "decision_count": decision_count,
        "range_checks": [dict(r) for r in range_checks], "lifecycle_probe": lifecycle_probe}
    return sanitize(payload)


def scan_rejected(sanitize: Sanitizer, *, engagement_id: str, target_index: int, code: str,
                  rule: str) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": SCHEMA, "engagement_id": engagement_id, "target_index": target_index,
        "code": code, "rule": rule}
    return sanitize(payload)


def scan_gate_error(sanitize: Sanitizer, *, engagement_id: str, reason: str, exc_class: str,
                    target_index: int) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": SCHEMA, "engagement_id": engagement_id, "reason": reason,
        "exc_class": exc_class, "target_index": target_index}
    return sanitize(payload)


async def append_entry(state: AppState, chain_id: str, kind: str, actor: str,
                       payload: Mapping[str, object]) -> LedgerEntry:
    """Append; ANY failure becomes ``ProblemError(503)``. Only the exception class is logged."""
    try:
        return await state.chain_backend.append(chain_id, kind, actor, payload,
                                                state.clock.now())
    except Exception as exc:  # noqa: BLE001 - never BaseException (cancellation propagates)
        cls = type(exc)
        log_event("ledger_write_failed", exc_class=f"{cls.__module__}.{cls.__qualname__}")
        raise ProblemError(503, ReasonCode.UNAVAILABLE, Detail.UNAVAILABLE,
                           headers={"Retry-After": "1"}) from None
