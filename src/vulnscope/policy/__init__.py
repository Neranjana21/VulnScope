"""Scope guard (policy/): every network action needs a policy decision first.

The package intentionally does not export ``decide``: the only production entry
point is ``decide_and_record``, which writes every allow and deny to the ledger.
"""

from __future__ import annotations

from vulnscope.policy.clock import Clock, SystemClock
from vulnscope.policy.decide_and_record import decide_and_record, policy_decision_to_payload
from vulnscope.policy.denylist import compute_policy_version
from vulnscope.policy.ratelimit import InMemoryRateLimitStore, RateLimitStore
from vulnscope.policy.resolver import ResolutionError, Resolver, SystemResolver
from vulnscope.policy.types import (
    Action,
    ActionKind,
    AuthorizationBasis,
    EngagementPolicyView,
    PolicyDecision,
    RuleId,
)

__all__ = (
    "Action",
    "ActionKind",
    "AuthorizationBasis",
    "Clock",
    "EngagementPolicyView",
    "InMemoryRateLimitStore",
    "PolicyDecision",
    "RateLimitStore",
    "ResolutionError",
    "Resolver",
    "RuleId",
    "SystemClock",
    "SystemResolver",
    "compute_policy_version",
    "decide_and_record",
    "policy_decision_to_payload",
)
