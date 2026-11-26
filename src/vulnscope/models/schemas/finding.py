"""Finding/Evidence view schemas, mirroring docs/io-contracts.md "Finding"
and "Evidence record" exactly."""

from __future__ import annotations

from typing import Self

from pydantic import Field, model_validator

from vulnscope.models.schemas.common import SchemaVersion1, StrictModel, UtcDateTime

# ADR-0012: the unscored placeholder. A made-up 0.0 is never used for "not scored".
UNSCORED = "unscored"
UNSCORED_UNKNOWN_INPUTS = ("cvss", "kev", "epss", "asset_criticality", "exposure")


class CvssInfo(StrictModel):
    version: str
    vector: str
    score: float | None
    source: str
    snapshot: str

    @model_validator(mode="after")
    def _unscored_is_exact(self) -> Self:
        if (self.score is None) != (self.version == UNSCORED):
            raise ValueError("score is null if and only if version is 'unscored'")
        placeholder = ("", "none", "none")
        if self.version == UNSCORED and (self.vector, self.source, self.snapshot) != placeholder:
            raise ValueError("unscored cvss requires empty vector and source/snapshot 'none'")
        return self


class Priority(StrictModel):
    band: str
    reasons: list[str] = Field(default_factory=list)
    policy_version: str
    unknown_inputs: list[str] = Field(default_factory=list)


class SourceAdapter(StrictModel):
    name: str
    version: str


class FindingView(StrictModel):
    id: str
    schema_version: SchemaVersion1
    org_id: str
    engagement_id: str
    asset_id: str
    title: str
    cwe: str | None = None
    taxonomy: list[str] = Field(default_factory=list)
    owasp_api: str | None = None
    status: str
    severity: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    cvss: CvssInfo
    priority: Priority
    source_adapter: SourceAdapter
    first_seen: UtcDateTime
    last_seen: UtcDateTime

    @model_validator(mode="after")
    def _unscored_is_consistent(self) -> Self:
        unscored = self.cvss.version == UNSCORED
        if (self.priority.band == UNSCORED) != unscored:
            raise ValueError("priority band 'unscored' goes with unscored cvss only")
        if unscored and (
            self.priority.reasons
            or self.priority.policy_version != "none"
            or tuple(self.priority.unknown_inputs) != UNSCORED_UNKNOWN_INPUTS
            or self.severity is not None
        ):
            raise ValueError("unscored findings require the ADR-0012 placeholder values")
        return self


class EvidenceView(StrictModel):
    id: str
    finding_id: str
    kind: str
    redacted_excerpt: str
    content_sha256: str
    identity_label: str | None = None
    expected: str | None = None
    observed: str | None = None
    policy_version: str
    adapter: SourceAdapter
    ledger_chain: str
    ledger_seq: int
    created_at: UtcDateTime
