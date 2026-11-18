"""Finding status state machine (docs/gates/slice0-plan.md Section 3.3,
AC5). Copied verbatim from the plan, which itself mirrors
docs/io-contracts.md's "Finding" status-transitions table exactly.

S0 has no transition API endpoint (no retest endpoint yet, per D11), so
this is exercised as a pure function only; the "reviewer role plus a
recorded reason" requirement for backward transitions is enforced once an
endpoint exists (tracked as OQ-3).
"""
from __future__ import annotations

from collections.abc import Mapping

TRANSITIONS: Mapping[str, frozenset[str]] = {
    "candidate": frozenset(
        {"likely", "confirmed", "false_positive", "inconclusive", "blocked_by_policy"}
    ),
    "likely": frozenset({"confirmed", "false_positive", "inconclusive"}),
    "inconclusive": frozenset({"likely", "confirmed", "false_positive"}),
    "confirmed": frozenset({"remediated"}),
    "remediated": frozenset({"confirmed"}),
    "blocked_by_policy": frozenset({"candidate"}),
    "false_positive": frozenset({"candidate"}),
}


def can_transition(current: str, target: str) -> bool:
    return target in TRANSITIONS.get(current, frozenset())
