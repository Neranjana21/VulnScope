"""Frozen input model for the Step 1 HTML report (ADR-0013).

To be implemented against it: ``render.render_report(model: ReportModel) -> str``,
standard library only, with ``html.escape`` on EVERY interpolated value (no template
engine and no template file). Every string here is to be treated as untrusted.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

from vulnscope.models.schemas.finding import EvidenceView, FindingView
from vulnscope.models.schemas.ledger import VerifyResponse

ReportOutcome = Literal["issue", "no_issue", "inconclusive", "denied", "revoked"]


@dataclass(frozen=True)
class EngagementFacts:
    engagement_id: str
    org_id: str
    profile: str
    status: str
    scope_allow: tuple[str, ...]
    scope_deny: tuple[str, ...]
    window_not_before: str
    window_not_after: str
    approver: str  # authorization is self-attested
    statement_sha256: str


@dataclass(frozen=True)
class DecisionFact:
    """One ``policy.decision`` ledger entry. Never holds the raw target."""

    ledger_seq: int
    allowed: bool
    rule_id: str
    reason: str


@dataclass(frozen=True)
class IntegrityProblem:
    code: str
    record_id: str  # a row id or a ledger payload id


@dataclass(frozen=True)
class IntegrityCheck:
    """The report-level ledger and row check. ``ok`` only if nothing is listed in either."""

    incomplete_reasons: tuple[str, ...]
    problems: tuple[IntegrityProblem, ...]

    @property
    def status(self) -> Literal["ok", "mismatch", "incomplete"]:
        if self.incomplete_reasons:
            return "incomplete"
        return "mismatch" if self.problems else "ok"


@dataclass(frozen=True)
class ReportModel:
    label: str
    engagement: EngagementFacts
    policy_version: str
    decisions: tuple[DecisionFact, ...]
    findings: tuple[FindingView, ...]
    evidence: tuple[EvidenceView, ...]
    evidence_checks: Mapping[str, bool]  # evidence id -> row, hash and chain entry agree
    outcome: ReportOutcome
    verify: VerifyResponse
    integrity: IntegrityCheck  # required: there is no default "ok"
