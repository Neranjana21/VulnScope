"""Policy types (plan 3.1 plus the additive fields of design sections 0 and 11.5).

``EngagementPolicyView`` is an immutable snapshot. Construction validates it and
pre-compiles the scope lists, so malformed entries fail at construction and never
at decision time. ``policy/`` never imports ``models/``; the API layer builds the
view per request so a revocation is seen on the next decision.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Literal

from vulnscope.policy.scope import CompiledScope, compile_scope

ActionKind = Literal["http", "tcp", "dns"]
ACTION_KINDS: tuple[str, ...] = ("http", "tcp", "dns")

_ENGAGEMENT_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,64}", re.ASCII)
_SHA256_RE = re.compile(r"[0-9a-f]{64}", re.ASCII)


@dataclass(frozen=True)
class Action:
    kind: ActionKind
    target: str  # raw target as given to decide(); hostile text, never trusted
    adapter: str  # which component is asking, for audit
    is_redirect_hop: bool = False


class RuleId(str, Enum):
    ALLOW = "ALLOW"
    DENY_ALWAYS_LIST = "DENY_ALWAYS_LIST"
    DENY_PRIVATE_RANGE = "DENY_PRIVATE_RANGE"
    EXCLUDED = "EXCLUDED"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    EXPIRED = "EXPIRED"
    NOT_YET_VALID = "NOT_YET_VALID"
    REVOKED = "REVOKED"
    RATE = "RATE"
    RESOLVED_OUTSIDE_EXPECTED = "RESOLVED_OUTSIDE_EXPECTED"
    REDIRECT_DENIED = "REDIRECT_DENIED"
    RESOLUTION_FAILED = "RESOLUTION_FAILED"


@dataclass(frozen=True)
class AuthorizationBasis:
    """What the operator attested to, by hash (the full statement stays in the DB row)."""

    confirmed: bool
    approver: str
    statement_sha256: str

    def __post_init__(self) -> None:
        if type(self.confirmed) is not bool:
            raise TypeError("confirmed must be a bool")
        if not isinstance(self.approver, str) or not 1 <= len(self.approver) <= 255:
            raise ValueError("approver must be 1..255 characters")
        if not isinstance(self.statement_sha256, str) or not _SHA256_RE.fullmatch(
            self.statement_sha256
        ):
            raise ValueError("statement_sha256 must be 64 lowercase hex characters")


@dataclass(frozen=True)
class CompiledEngagement:
    allow: CompiledScope
    deny: CompiledScope
    expected: CompiledScope


def _require_aware(value: datetime, name: str) -> None:
    if not isinstance(value, datetime):
        raise TypeError(f"{name} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware")


@dataclass(frozen=True)
class EngagementPolicyView:
    engagement_id: str
    org_id: str
    profile: Literal["standard", "lab"]
    status: str  # "active" is the only value that can allow; anything else fails closed
    scope_allow: tuple[str, ...]
    scope_deny: tuple[str, ...]
    expected_ip_ranges: tuple[str, ...]
    rate_limit_rps: float
    window_not_before: datetime
    window_not_after: datetime
    policy_version: str
    authorization_basis: AuthorizationBasis | None = None
    compiled: CompiledEngagement = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.engagement_id, str) or not _ENGAGEMENT_ID_RE.fullmatch(
            self.engagement_id
        ):
            raise ValueError("engagement_id must match [A-Za-z0-9_-]{1,64}")
        if self.profile not in ("standard", "lab"):
            raise ValueError("unknown profile")
        _require_aware(self.window_not_before, "window_not_before")
        _require_aware(self.window_not_after, "window_not_after")
        if self.window_not_after <= self.window_not_before:
            raise ValueError("window_not_after must be after window_not_before")
        rps = self.rate_limit_rps
        if isinstance(rps, bool) or not isinstance(rps, int | float):
            raise TypeError("rate_limit_rps must be a number")
        if not math.isfinite(rps) or rps <= 0:
            raise ValueError("rate_limit_rps must be finite and positive")
        if self.authorization_basis is not None and not isinstance(
            self.authorization_basis, AuthorizationBasis
        ):
            raise TypeError("authorization_basis must be an AuthorizationBasis")
        for name in ("scope_allow", "scope_deny", "expected_ip_ranges"):
            object.__setattr__(self, name, tuple(getattr(self, name)))
        compiled = CompiledEngagement(
            allow=compile_scope(self.scope_allow, "allow"),
            deny=compile_scope(self.scope_deny, "deny"),
            expected=compile_scope(self.expected_ip_ranges, "expected"),
        )
        object.__setattr__(self, "compiled", compiled)


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str
    rule_id: RuleId
    policy_version: str
    action: Action
    resolved_ips: tuple[str, ...]
    ts: datetime
    ledger_seq: int | None = None
