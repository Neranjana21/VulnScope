"""Finding/Evidence view schemas, mirroring docs/io-contracts.md "Finding"
and "Evidence record" exactly."""
from __future__ import annotations

from pydantic import Field

from vulnscope.models.schemas.common import SchemaVersion1, StrictModel, UtcDateTime


class CvssInfo(StrictModel):
    version: str
    vector: str
    score: float
    source: str
    snapshot: str


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
