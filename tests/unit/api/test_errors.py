"""PD-02: the error vocabularies are pinned by EXACT sets (ADR-0006 decision 1)."""
from __future__ import annotations

import ast
from pathlib import Path

import pytest
from pydantic import ValidationError

from vulnscope.errors import PolicyReasonCode, ProblemDetail, ReasonCode

CONTRACT_15 = {
    "AUTH_NOT_CONFIRMED", "SCOPE_EMPTY", "TARGET_DENIED", "TARGET_NOT_IN_SCOPE",
    "RATE_ABOVE_CEILING", "WINDOW_MISSING", "WINDOW_EXPIRED", "WINDOW_NAIVE_DATETIME",
    "WINDOW_TOO_LONG", "SECRET_INLINE", "UNKNOWN_FIELD", "PROFILE_NOT_ENABLED",
    "IDEMPOTENCY_CONFLICT", "FORBIDDEN_ROLE", "NOT_FOUND",
}
ADR_0006_FOUR = {"UNAUTHENTICATED", "INVALID_REQUEST", "INTERNAL_ERROR", "UNAVAILABLE"}


def test_reason_code_is_the_contract_plus_exactly_four() -> None:
    assert {m.value for m in ReasonCode} == CONTRACT_15 | ADR_0006_FOUR
    assert len(ReasonCode) == 19


def test_policy_reason_code_is_exactly_revoked_and_expired() -> None:
    assert {m.value for m in PolicyReasonCode} == {"REVOKED", "EXPIRED"}


@pytest.mark.parametrize("code", sorted(CONTRACT_15 | ADR_0006_FOUR | {"REVOKED", "EXPIRED"}))
def test_problem_detail_accepts_every_code(code: str) -> None:
    p = ProblemDetail(title="t", status=400, detail="d", code=code)  # type: ignore[arg-type]
    dumped = p.model_dump(mode="json")
    assert isinstance(dumped["code"], str) and dumped["code"] == code


@pytest.mark.parametrize("bad", ["RATE", "", "rate_limited", "NOT_YET_VALID", "revoked"])
def test_problem_detail_rejects_other_codes(bad: str) -> None:
    with pytest.raises(ValidationError):
        ProblemDetail(title="t", status=400, detail="d", code=bad)  # type: ignore[arg-type]


def test_problem_detail_forbids_extra_fields() -> None:
    with pytest.raises(ValidationError):
        ProblemDetail(title="t", status=400, detail="d", code="NOT_FOUND", extra=1)  # type: ignore[call-arg]


def test_errors_module_does_not_import_policy() -> None:
    src = Path(__file__).resolve().parents[3] / "src" / "vulnscope" / "errors.py"
    for node in ast.walk(ast.parse(src.read_text(encoding="utf-8"))):
        if isinstance(node, ast.ImportFrom) and node.module:
            assert not node.module.startswith("vulnscope.policy")
        if isinstance(node, ast.Import):
            assert all(not a.name.startswith("vulnscope.policy") for a in node.names)
