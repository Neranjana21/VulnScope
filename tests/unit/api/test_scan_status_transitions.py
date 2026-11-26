"""N-04 (owner condition 2026-11-24): every allowed scan-status transition is listed in ADR-0006,
`cancelled` is terminal and never restartable, and every other (from, to) pair is rejected."""
from __future__ import annotations

import ast
import itertools
from pathlib import Path

import pytest
from pydantic import ValidationError

from vulnscope.api.scan_status import (
    ALLOWED_TRANSITIONS,
    SCAN_STATUSES,
    assert_transition,
    is_allowed_transition,
)
from vulnscope.models.schemas.views import ScanStatusView

ROOT = Path(__file__).resolve().parents[3]
EXPECTED = {
    ("pending", "queued"),
    ("pending", "cancelled"),
    ("queued", "running"),
    ("queued", "cancelled"),
    ("running", "cancelled"),
}
JUNK = ["done", "", "CANCELLED", "completed", "failed"]


def test_statuses_are_exactly_the_four() -> None:
    assert set(SCAN_STATUSES) == {"pending", "queued", "running", "cancelled"}


def test_allowed_transition_set_is_exactly_the_approved_list() -> None:
    assert set(ALLOWED_TRANSITIONS) == EXPECTED


@pytest.mark.parametrize("frm,to", list(itertools.product([*SCAN_STATUSES, *JUNK], repeat=2)))
def test_every_pair_is_decided_by_the_list(frm: str, to: str) -> None:
    allowed = (frm, to) in EXPECTED
    assert is_allowed_transition(frm, to) is allowed
    if allowed:
        assert_transition(frm, to)
    else:
        with pytest.raises(ValueError):
            assert_transition(frm, to)


def test_cancelled_is_terminal_and_pending_is_never_re_entered() -> None:
    assert not any(f == "cancelled" for f, _ in EXPECTED)
    assert not any(t == "pending" for _, t in EXPECTED)
    for to in SCAN_STATUSES:
        assert not is_allowed_transition("cancelled", to)


def test_adr_0006_lists_every_allowed_transition() -> None:
    adr = (ROOT / "docs" / "adr" / "0006-api-auth-idempotency-errors-revoke.md").read_text(
        encoding="utf-8")
    for frm, to in sorted(EXPECTED):
        assert f"{frm} -> {to}" in adr, f"ADR-0006 does not list {frm} -> {to}"
    assert "cancelled is terminal" in adr.lower().replace("`", "")


@pytest.mark.parametrize("status", sorted(SCAN_STATUSES))
def test_scan_view_accepts_the_four_statuses(status: str) -> None:
    v = ScanStatusView.model_validate({
        "id": "s1", "schema_version": 1, "engagement_id": "e1", "status": status,
        "stages": ["discover"], "options": {"write_tests": False}, "schedule": None})
    assert v.status == status


@pytest.mark.parametrize("status", JUNK)
def test_scan_view_rejects_other_statuses(status: str) -> None:
    with pytest.raises(ValidationError):
        ScanStatusView.model_validate({
            "id": "s1", "schema_version": 1, "engagement_id": "e1", "status": status,
            "stages": ["discover"], "options": {"write_tests": False}, "schedule": None})


def test_scan_status_is_written_only_through_scan_status_module() -> None:
    api = ROOT / "src" / "vulnscope" / "api"
    for path in api.rglob("*.py"):
        if path.name == "scan_status.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                    and node.func.id == "update" and node.args \
                    and isinstance(node.args[0], ast.Name) and node.args[0].id == "Scan":
                pytest.fail(f"{path.name} updates scans outside scan_status.py")
            if isinstance(node, ast.Constant) and isinstance(node.value, str) \
                    and "update scans" in node.value.lower():
                pytest.fail(f"{path.name} contains raw SQL updating scans")
