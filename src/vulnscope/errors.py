"""RFC 9457 ``application/problem+json`` error shape and the reason-code
enum, copied verbatim from ``docs/io-contracts.md`` ("Reason codes" /
"Conventions") -- not re-derived, per the plan's contract-fidelity rule.
"""
from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict


class ReasonCode(str, Enum):
    """Request-validation reason codes, verbatim from
    docs/io-contracts.md's "Reason codes" section."""

    AUTH_NOT_CONFIRMED = "AUTH_NOT_CONFIRMED"
    SCOPE_EMPTY = "SCOPE_EMPTY"
    TARGET_DENIED = "TARGET_DENIED"
    TARGET_NOT_IN_SCOPE = "TARGET_NOT_IN_SCOPE"
    RATE_ABOVE_CEILING = "RATE_ABOVE_CEILING"
    WINDOW_MISSING = "WINDOW_MISSING"
    WINDOW_EXPIRED = "WINDOW_EXPIRED"
    WINDOW_NAIVE_DATETIME = "WINDOW_NAIVE_DATETIME"
    WINDOW_TOO_LONG = "WINDOW_TOO_LONG"
    SECRET_INLINE = "SECRET_INLINE"
    UNKNOWN_FIELD = "UNKNOWN_FIELD"
    PROFILE_NOT_ENABLED = "PROFILE_NOT_ENABLED"
    IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT"
    FORBIDDEN_ROLE = "FORBIDDEN_ROLE"
    NOT_FOUND = "NOT_FOUND"


class ProblemDetail(BaseModel):
    """RFC 9457 problem+json body, extended with the three extra fields
    docs/io-contracts.md's "Conventions" section requires: ``code``,
    ``ledger_seq`` (if a ledger entry was written for this rejection),
    ``request_id``.
    """

    model_config = ConfigDict(extra="forbid")

    type: str = "about:blank"
    title: str
    status: int
    detail: str
    instance: str | None = None
    code: ReasonCode
    ledger_seq: int | None = None
    request_id: str | None = None
