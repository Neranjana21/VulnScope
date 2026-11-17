"""API-facing mirror of ``policy.types.PolicyDecision`` (Task A), matching
docs/io-contracts.md "Policy decision" exactly. ``policy/`` itself never
imports this module (purity rule, Section 2 of the plan) -- only
``api/policy_integration.py`` (Task D) builds one of these from a
``PolicyDecision`` dataclass.
"""
from __future__ import annotations

from typing import Literal

from pydantic import Field

from vulnscope.models.schemas.common import StrictModel, UtcDateTime


class PolicyActionView(StrictModel):
    kind: Literal["http", "tcp", "dns"]
    target: str
    resolved_ips: list[str] = Field(default_factory=list)
    adapter: str


class PolicyDecisionView(StrictModel):
    allowed: bool
    reason: str
    rule_id: str
    policy_version: str
    action: PolicyActionView
    ts: UtcDateTime
