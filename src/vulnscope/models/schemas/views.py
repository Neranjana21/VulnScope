"""Additive response views for the API (Task D). Existing schemas are untouched.

``ScanStatusView`` narrows ``ScanView.status`` to the four documented scan statuses (ADR-0006
decision 9). ``EngagementView`` never exposes ``secret_ref`` (rule 6)."""
from __future__ import annotations

from typing import Any, Literal

from vulnscope.models.schemas.common import SchemaVersion1, StrictModel, UtcDateTime
from vulnscope.models.schemas.engagement import (
    AssetTag,
    Authorization,
    OwnershipRule,
    Scope,
    Targets,
)
from vulnscope.models.schemas.ledger import VerifyResponse
from vulnscope.models.schemas.scan import ScanOptions, ScanStage

ScanStatus = Literal["pending", "queued", "running", "cancelled"]


class ScanStatusView(StrictModel):
    id: str
    schema_version: SchemaVersion1
    engagement_id: str
    status: ScanStatus
    stages: list[ScanStage]
    options: ScanOptions
    schedule: dict[str, Any] | None = None


class IdentityAuthView(StrictModel):
    type: Literal["bearer", "api_key_header", "basic"]


class IdentityView(StrictModel):
    label: str
    role: str
    auth: IdentityAuthView


class EngagementView(StrictModel):
    id: str
    schema_version: SchemaVersion1
    name: str
    profile: Literal["standard", "lab"]
    status: Literal["active", "revoked"]
    targets: Targets
    scope: Scope
    authorization: Authorization
    identities: list[IdentityView]
    ownership_rules: list[OwnershipRule]
    asset_tags: list[AssetTag]
    created_at: UtcDateTime
    revoked_at: UtcDateTime | None = None
    revoked_reason: str | None = None


class FindingsEnvelope(StrictModel):
    schema_version: SchemaVersion1 = 1
    items: list[Any] = []


class PathsEnvelope(StrictModel):
    schema_version: SchemaVersion1 = 1
    items: list[Any] = []
    paths_total: int = 0


class ReportStub(StrictModel):
    schema_version: SchemaVersion1 = 1
    scan_id: str
    engagement_id: str
    status: ScanStatus
    note: str
    scope: dict[str, Any]
    findings: list[Any]
    paths: list[Any]
    ledger_verification: dict[str, Any]


__all__ = [
    "EngagementView", "FindingsEnvelope", "PathsEnvelope", "ReportStub", "ScanStatusView",
    "VerifyResponse",
]
