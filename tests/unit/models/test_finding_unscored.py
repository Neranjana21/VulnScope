"""ADR-0012: the unscored placeholder. Null score if and only if version is "unscored"."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest
from pydantic import ValidationError

from vulnscope.models.schemas.finding import CvssInfo, FindingView

UNKNOWN = ["cvss", "kev", "epss", "asset_criticality", "exposure"]
UNSCORED_CVSS: dict[str, Any] = {
    "version": "unscored",
    "score": None,
    "vector": "",
    "source": "none",
    "snapshot": "none",
}
UNSCORED_PRIORITY: dict[str, Any] = {
    "band": "unscored",
    "reasons": [],
    "policy_version": "none",
    "unknown_inputs": UNKNOWN,
}
SCORED_CVSS: dict[str, Any] = {
    "version": "4.0",
    "score": 5.3,
    "vector": "CVSS:4.0/AV:N",
    "source": "nvd",
    "snapshot": "2026-01-01",
}
SCORED_PRIORITY: dict[str, Any] = {
    "band": "medium",
    "reasons": ["reachable"],
    "policy_version": "1",
    "unknown_inputs": [],
}


def finding(
    cvss: dict[str, Any], priority: dict[str, Any], severity: str | None = None
) -> dict[str, Any]:
    return copy.deepcopy(
        {
            "id": "f1",
            "schema_version": 1,
            "org_id": "o1",
            "engagement_id": "e1",
            "asset_id": "a1",
            "title": "t",
            "status": "confirmed",
            "severity": severity,
            "cvss": cvss,
            "priority": priority,
            "source_adapter": {"name": "n", "version": "1"},
            "first_seen": "2026-01-01T00:00:00Z",
            "last_seen": "2026-01-01T00:00:00Z",
        }
    )


def validate(payload: dict[str, Any]) -> FindingView:
    return FindingView.model_validate_json(json.dumps(payload))


def test_unscored_placeholder_is_valid_and_round_trips() -> None:
    view = validate(finding(UNSCORED_CVSS, UNSCORED_PRIORITY))
    assert view.cvss.score is None
    assert view.severity is None
    dumped = view.model_dump(mode="json")
    assert dumped["cvss"] == UNSCORED_CVSS
    assert dumped["priority"] == UNSCORED_PRIORITY


def test_scored_finding_stays_valid() -> None:
    assert validate(finding(SCORED_CVSS, SCORED_PRIORITY, "medium")).cvss.score == 5.3


def test_score_must_still_be_stated() -> None:
    cvss = {k: v for k, v in UNSCORED_CVSS.items() if k != "score"}
    with pytest.raises(ValidationError):
        CvssInfo.model_validate(cvss)


@pytest.mark.parametrize(
    "cvss",
    [
        {**UNSCORED_CVSS, "score": 0.0},
        {**UNSCORED_CVSS, "score": 5.0},
        {**SCORED_CVSS, "score": None},
        {**UNSCORED_CVSS, "vector": "CVSS:4.0/AV:N"},
        {**UNSCORED_CVSS, "source": "nvd"},
        {**UNSCORED_CVSS, "snapshot": "2026-01-01"},
    ],
    ids=["fake-zero", "unscored-with-score", "scored-null", "vector", "source", "snapshot"],
)
def test_invalid_cvss_states(cvss: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        CvssInfo.model_validate(cvss)


@pytest.mark.parametrize(
    ("cvss", "priority", "severity"),
    [
        (UNSCORED_CVSS, UNSCORED_PRIORITY, "low"),
        (UNSCORED_CVSS, {**UNSCORED_PRIORITY, "band": "high"}, None),
        (UNSCORED_CVSS, {**UNSCORED_PRIORITY, "reasons": ["x"]}, None),
        (UNSCORED_CVSS, {**UNSCORED_PRIORITY, "policy_version": "1"}, None),
        (UNSCORED_CVSS, {**UNSCORED_PRIORITY, "unknown_inputs": []}, None),
        (UNSCORED_CVSS, {**UNSCORED_PRIORITY, "unknown_inputs": UNKNOWN[:4]}, None),
        (SCORED_CVSS, UNSCORED_PRIORITY, "medium"),
    ],
    ids=["severity", "band", "reasons", "policy", "no-unknowns", "partial", "scored-band"],
)
def test_invalid_finding_states(
    cvss: dict[str, Any], priority: dict[str, Any], severity: str | None
) -> None:
    with pytest.raises(ValidationError):
        validate(finding(cvss, priority, severity))
