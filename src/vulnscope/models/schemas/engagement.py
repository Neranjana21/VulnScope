"""Engagement request/response schemas, mirroring docs/io-contracts.md
"Engagement" exactly."""
from __future__ import annotations

from typing import Literal

from pydantic import Field

from vulnscope.models.schemas.common import SchemaVersion1, StrictModel, UtcDateTime


class Window(StrictModel):
    not_before: UtcDateTime
    not_after: UtcDateTime


class Scope(StrictModel):
    allow: list[str] = Field(default_factory=list)
    deny: list[str] = Field(default_factory=list)
    expected_ip_ranges: list[str] = Field(default_factory=list)
    rate_limit_rps: float
    window: Window


class Targets(StrictModel):
    domains: list[str] = Field(default_factory=list)
    ip_ranges: list[str] = Field(default_factory=list)
    openapi_url: str | None = None


class Authorization(StrictModel):
    confirmed: bool
    statement: str
    approver: str


class IdentityAuth(StrictModel):
    type: Literal["bearer", "api_key_header", "basic"]
    secret_ref: str = Field(pattern=r"^ref://[a-z0-9_/-]+$")


class Identity(StrictModel):
    label: str
    role: str
    auth: IdentityAuth


class OwnershipRule(StrictModel):
    resource: str
    owner_identity: str


class AssetTag(StrictModel):
    match: str
    criticality: str
    data: str


class EngagementCreateRequest(StrictModel):
    schema_version: SchemaVersion1
    name: str
    profile: Literal["standard", "lab"]
    targets: Targets
    scope: Scope
    authorization: Authorization
    identities: list[Identity] = Field(default_factory=list)
    ownership_rules: list[OwnershipRule] = Field(default_factory=list)
    asset_tags: list[AssetTag] = Field(default_factory=list)


class EngagementCreateResponse(StrictModel):
    id: str
    status: Literal["active"]
    created_at: UtcDateTime
    ledger_seq: int


class EngagementRevokeRequest(StrictModel):
    reason: str


class EngagementRevokeResponse(StrictModel):
    status: Literal["revoked"]
    revoked_at: UtcDateTime
    ledger_seq: int
