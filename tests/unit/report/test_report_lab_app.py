"""ADR-0014: report wording must be true for the target that was checked."""

from __future__ import annotations

import dataclasses

import pytest
from test_report_remediation import excerpt_for, with_excerpt
from test_report_render import HEADINGS, _text, make_model

from vulnscope.report.model import ReportModel
from vulnscope.report.render import LABEL, render_report
from vulnscope.validate.types import HEADER_NAMES


def excerpt_all_absent() -> ReportModel:
    return with_excerpt(excerpt_for(*HEADER_NAMES))


def lab_model() -> ReportModel:
    return dataclasses.replace(excerpt_all_absent(), target_kind="lab_app")


def test_the_lab_report_makes_no_stub_claim() -> None:
    document = render_report(lab_model())
    lowered = document.lower()
    for forbidden in ("stub", "temporary", "run the demo again", "demo's own"):
        assert forbidden not in lowered, forbidden
    assert LABEL in _text(document)


def test_the_lab_reproduce_line() -> None:
    text = _text(render_report(lab_model()))
    findings = text.split(HEADINGS[3], 1)[1].split(HEADINGS[4], 1)[0]
    assert findings.count("How to reproduce") == len(HEADER_NAMES)
    assert "HEAD / was sent to the lab app on 127.0.0.1:3000" in findings
    assert "cannot verify that the app is Juice Shop" in findings
    assert "devpath.step1b" in findings


@pytest.mark.parametrize(
    "phrase",
    [
        "one HEAD request to the lab app on 127.0.0.1:3000",
        "Port 3000 cannot identify Juice Shop",
        "cannot verify that whatever listens there is Juice Shop",
        "The operator attests it",
        "lab isolation not verified",
        "lab hygiene, not the worker boundary",
        "deliberately vulnerable lab app",
        "present or absent",
        "Cookies, server banners, paths other than /, GET requests and response bodies are "
        "not examined",
        "No redirect is followed",
        "No egress gateway, worker, queue, job token, process or network isolation",
        "not the security boundary and not a Slice 1 result",
        "SEC-6",
        "GR-SEC-9",
        "SEC-6 and GR-SEC-9 remain open",
        "both directions",
        "after that re-read",
        "self-attested",
        "Findings are unscored",
        "No checkpoint",
    ],
)
def test_the_lab_limits_are_stated(phrase: str) -> None:
    limits = _text(render_report(lab_model())).split("Limits of this assessment", 1)[1]
    assert phrase in limits


def test_the_own_stub_report_makes_no_lab_app_claim() -> None:
    text = _text(render_report(excerpt_all_absent()))
    assert "demo's own local stub" in text and "run the demo again" in text
    for forbidden in ("127.0.0.1:3000", "Juice Shop", "lab isolation not verified"):
        assert forbidden not in text


@pytest.mark.parametrize("kind", ["", "juice", "own_stub ", None])
def test_an_unknown_target_kind_fails_closed(kind: object) -> None:
    with pytest.raises(ValueError):
        render_report(dataclasses.replace(make_model(), target_kind=kind))  # type: ignore[arg-type]
