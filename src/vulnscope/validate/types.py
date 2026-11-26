"""Frozen interface types for the Step 1 security-header check (ADR-0013).

Round 25: exactly five header names, verdicts ``absent`` or ``present`` only (literal
presence). Header values are never judged, stored or logged; there are no bodies.

To be implemented against these types:
``security_headers.evaluate(response: HeaderResponse) -> CheckResult`` and
``evidence.build_evidence(result: CheckResult) -> RedactedEvidence``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, get_args

HeaderName = Literal[
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]
HEADER_NAMES: tuple[HeaderName, ...] = get_args(HeaderName)

Verdict = Literal["absent", "present"]
Outcome = Literal["issue", "no_issue", "inconclusive"]
InconclusiveReason = Literal["redirect_not_followed", "unexpected_status"]


@dataclass(frozen=True)
class HeaderResponse:
    """Status and raw headers from the target. HOSTILE data: held in memory only.

    ``headers`` is left out of ``repr`` so that printing or logging the object cannot
    emit target bytes.
    """

    status: int
    headers: tuple[tuple[bytes, bytes], ...] = field(repr=False)


@dataclass(frozen=True)
class CheckResult:
    """Closed vocabulary only: nothing here can carry target bytes.

    ``reason`` is set for ``inconclusive`` outcomes and is None otherwise.
    """

    outcome: Outcome
    verdicts: tuple[tuple[HeaderName, Verdict], ...]
    reason: InconclusiveReason | None


@dataclass(frozen=True)
class RedactedEvidence:
    """``content_sha256`` is the SHA-256 of the stored excerpt bytes (UTF-8)."""

    excerpt: str
    content_sha256: str
