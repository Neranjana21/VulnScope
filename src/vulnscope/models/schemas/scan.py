"""Scan request/response schemas, mirroring docs/io-contracts.md "Scan"
exactly."""
from __future__ import annotations

from typing import Any, Literal

from pydantic import Field

from vulnscope.models.schemas.common import SchemaVersion1, StrictModel

ScanStage = Literal["discover", "detect", "validate", "path"]


class ScanOptions(StrictModel):
    write_tests: bool = False


class ScanCreateRequest(StrictModel):
    schema_version: SchemaVersion1
    stages: list[ScanStage]
    options: ScanOptions = Field(default_factory=ScanOptions)
    schedule: dict[str, Any] | None = None


class ScanCreateResponse(StrictModel):
    scan_id: str
    status: Literal["queued"]


class ScanView(StrictModel):
    id: str
    schema_version: SchemaVersion1
    engagement_id: str
    status: str
    stages: list[ScanStage]
    options: ScanOptions
    schedule: dict[str, Any] | None = None
