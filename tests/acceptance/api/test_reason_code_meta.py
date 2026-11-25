"""Meta-test (PD-18): every contract reason code has an acceptance case. No other code is exempt
than INTERNAL_ERROR and UNAVAILABLE (they need fault injection; integration tests cover them).

The cases declare the codes they assert with ``@pytest.mark.covers_code("CODE")`` (also inside
``pytest.param(..., marks=...)``). This test reads the test sources with ``ast`` so it does not
depend on collection order or on which files were selected."""
from __future__ import annotations

import ast
from pathlib import Path

from vulnscope.errors import PolicyReasonCode, ReasonCode

HERE = Path(__file__).resolve().parent
EXEMPT = {"INTERNAL_ERROR", "UNAVAILABLE"}
CONTRACT_15 = {
    "AUTH_NOT_CONFIRMED", "SCOPE_EMPTY", "TARGET_DENIED", "TARGET_NOT_IN_SCOPE",
    "RATE_ABOVE_CEILING", "WINDOW_MISSING", "WINDOW_EXPIRED", "WINDOW_NAIVE_DATETIME",
    "WINDOW_TOO_LONG", "SECRET_INLINE", "UNKNOWN_FIELD", "PROFILE_NOT_ENABLED",
    "IDEMPOTENCY_CONFLICT", "FORBIDDEN_ROLE", "NOT_FOUND"}


def _declared() -> set[str]:
    out: set[str] = set()
    for path in HERE.glob("test_*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "covers_code"):
                out.update(a.value for a in node.args
                           if isinstance(a, ast.Constant) and isinstance(a.value, str))
    return out


def test_enums_are_exactly_the_documented_sets() -> None:
    assert {c.value for c in ReasonCode} == CONTRACT_15 | {
        "UNAUTHENTICATED", "INVALID_REQUEST", "INTERNAL_ERROR", "UNAVAILABLE"}
    assert {c.value for c in PolicyReasonCode} == {"REVOKED", "EXPIRED"}


def test_every_reason_code_has_an_acceptance_case() -> None:
    every = {c.value for c in ReasonCode} | {c.value for c in PolicyReasonCode}
    missing = every - _declared() - EXEMPT
    assert not missing, f"codes without an acceptance case: {sorted(missing)}"


def test_declared_codes_exist_and_exemptions_are_exactly_two() -> None:
    every = {c.value for c in ReasonCode} | {c.value for c in PolicyReasonCode}
    assert _declared() <= every
    assert EXEMPT <= every and len(EXEMPT) == 2
    assert not (EXEMPT & _declared()), "an exempt code gained a case: remove it from EXEMPT"
