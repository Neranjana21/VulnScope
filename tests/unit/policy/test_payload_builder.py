"""policy_decision_to_payload ends with sanitize_payload (design 11.5)."""

from __future__ import annotations

import ast
from pathlib import Path

from policy_test_support import run_decide

import vulnscope.policy as pkg
from vulnscope.policy.decide_and_record import policy_decision_to_payload
from vulnscope.policy.types import AuthorizationBasis


def test_last_statement_is_return_sanitize_payload() -> None:
    tree = ast.parse(
        (Path(pkg.__file__).parent / "decide_and_record.py").read_text(encoding="utf-8")
    )
    fn = next(
        n
        for n in tree.body
        if isinstance(n, ast.FunctionDef) and n.name == "policy_decision_to_payload"
    )
    last = fn.body[-1]
    assert isinstance(last, ast.Return) and isinstance(last.value, ast.Call)
    assert isinstance(last.value.func, ast.Name) and last.value.func.id == "sanitize_payload"


def test_hostile_target_is_recorded_sanitized_and_basis_kept() -> None:
    d, _ = run_decide("a\x00b\ud800" + "x" * 5000, allow=("a.test",))
    basis = AuthorizationBasis(True, "user:1", "c" * 64)
    p = policy_decision_to_payload(d, authorization_basis=basis)
    assert p["authorization_basis"] == {
        "confirmed": True,
        "approver": "user:1",
        "statement_sha256": "c" * 64,
    }
    assert "\x00" not in repr(p)


def test_lab_cidr_field_variants() -> None:
    d, _ = run_decide("192.0.2.1", allow=("192.0.2.1",))
    assert policy_decision_to_payload(d)["lab_cidr"] is None
    assert policy_decision_to_payload(d, lab_enabled=True, lab_cidr="10.0.0.0/8")["lab_cidr"] == (
        "10.0.0.0/8"
    )
    assert policy_decision_to_payload(d, lab_enabled=True, lab_cidr="junk")["lab_cidr"] == "junk"
    assert policy_decision_to_payload(d, lab_enabled=False, lab_cidr="junk")["lab_cidr"] is None
