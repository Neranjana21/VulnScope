"""Per-finding remediation and the static fix snippets, derived only from verified evidence."""

from __future__ import annotations

import dataclasses
import hashlib
from typing import Any

import pytest
from test_report_render import HEADINGS, _integrity, _text, make_model

from vulnscope.report import render as render_module
from vulnscope.report.model import ReportModel
from vulnscope.report.render import render_report
from vulnscope.validate.types import HEADER_NAMES

NOT_SHOWN = "remediation not shown: evidence could not be verified"
CANARY = "canary-5d1e8b"


def excerpt_for(*absent: str) -> str:
    return "\n".join(f"{n}: {'absent' if n in absent else 'present'}" for n in HEADER_NAMES)


def with_excerpt(excerpt: str, **changes: Any) -> ReportModel:
    """The stored hash and the runner check agree, so only the content is in question."""
    base = make_model()
    item = base.evidence[0].model_copy(
        update={
            "redacted_excerpt": excerpt,
            "content_sha256": hashlib.sha256(excerpt.encode()).hexdigest(),
        }
    )
    return dataclasses.replace(base, evidence=(item,), **changes)


def section(document: str, index: int) -> str:
    return _text(document).split(HEADINGS[index], 1)[1].split(HEADINGS[index + 1], 1)[0]


def reproduce_lines(text: str) -> int:
    return text.count("How to reproduce")


@pytest.mark.parametrize("name", HEADER_NAMES)
def test_each_absent_header_gets_its_own_remediation_and_reproduce_line(name: str) -> None:
    findings = section(render_report(with_excerpt(excerpt_for(name))), 3)
    assert NOT_SHOWN not in findings
    assert reproduce_lines(findings) == 1
    assert f"Absent header: {name}" in findings
    assert f"the response had no {name} header" in findings
    assert "HEAD /" in findings and "127.0.0.1" in findings
    assert "temporary" in findings and "run the demo again" in findings
    for other in set(HEADER_NAMES) - {name}:
        assert f"Absent header: {other}" not in findings


def test_all_five_absent_have_distinct_remediation_texts() -> None:
    findings = section(render_report(with_excerpt(excerpt_for(*HEADER_NAMES))), 3)
    assert reproduce_lines(findings) == 5
    texts = [line for line in findings.split("\n") if line.startswith("Send ")]
    assert len(set(texts)) == 5
    assert "frame-ancestors rule does not count as X-Frame-Options for this check" in findings
    assert "presence-only" in findings
    assert "does not show that" in findings


def test_remediation_follows_the_finding_it_belongs_to() -> None:
    text = section(render_report(with_excerpt(excerpt_for("referrer-policy"))), 3)
    assert text.index("Finding: ") < text.index("Evidence cross-check") < text.index("Remediation")


def test_no_absent_header_shows_no_remediation() -> None:
    findings = section(render_report(with_excerpt(excerpt_for())), 3)
    assert reproduce_lines(findings) == 0
    assert "marks no header as absent" in findings


GOOD = excerpt_for("x-frame-options")


@pytest.mark.parametrize(
    "excerpt",
    [
        "",
        "x-frame-options: absent",
        GOOD + "\n",
        GOOD + "\n" + CANARY,
        GOOD.replace("\n", "\r\n"),
        GOOD.replace("x-frame-options: absent", "x-frame-options: " + CANARY),
        GOOD.replace("x-frame-options: absent", CANARY + ": absent"),
        GOOD.replace("x-frame-options: absent", "x-frame-options:  absent"),
        GOOD.replace("x-frame-options", "X-Frame-Options"),
        "\n".join(reversed(GOOD.split("\n"))),
        "\n".join([GOOD.split("\n")[0]] * 5),
        "inconclusive: unexpected_status",
    ],
)
def test_an_excerpt_not_in_the_exact_format_shows_the_fixed_line(excerpt: str) -> None:
    findings = section(render_report(with_excerpt(excerpt)), 3)
    assert NOT_SHOWN in findings
    assert reproduce_lines(findings) == 0
    # The canary appears only where the stored excerpt itself is shown.
    assert findings.count(CANARY) == excerpt.count(CANARY)


def _unverified_models() -> dict[str, ReportModel]:
    good = with_excerpt(GOOD)
    item = good.evidence[0]
    second = item.model_copy(update={"id": "ev2"})
    other = excerpt_for("referrer-policy")
    differing = second.model_copy(
        update={
            "redacted_excerpt": other,
            "content_sha256": hashlib.sha256(other.encode()).hexdigest(),
        }
    )
    both = good.findings[0].model_copy(update={"evidence_ids": [item.id, "ev2"]})
    return {
        "runner_check_failed": dataclasses.replace(good, evidence_checks={item.id: False}),
        "unchecked": dataclasses.replace(good, evidence_checks={}),
        "hash_differs": dataclasses.replace(
            good, evidence=(item.model_copy(update={"content_sha256": "0" * 64}),)
        ),
        "no_evidence": dataclasses.replace(good, evidence=()),
        "listed_row_missing": dataclasses.replace(good, findings=(both,)),
        "unlisted_extra_row": dataclasses.replace(
            good, evidence=(item, second), evidence_checks={item.id: True, "ev2": True}
        ),
        "rows_disagree": dataclasses.replace(
            good,
            findings=(both,),
            evidence=(item, differing),
            evidence_checks={item.id: True, "ev2": True},
        ),
        "one_of_two_unverified": dataclasses.replace(
            good, findings=(both,), evidence=(item, second)
        ),
        "integrity_mismatch": dataclasses.replace(
            good, integrity=_integrity(codes=("evidence_row_differs",))
        ),
        "integrity_incomplete": dataclasses.replace(
            good, integrity=_integrity(reasons=("ledger_read_bounded",))
        ),
    }


@pytest.mark.parametrize(
    "case",
    [
        "runner_check_failed",
        "unchecked",
        "hash_differs",
        "no_evidence",
        "listed_row_missing",
        "unlisted_extra_row",
        "rows_disagree",
        "one_of_two_unverified",
        "integrity_mismatch",
        "integrity_incomplete",
    ],
)
def test_unverified_evidence_shows_the_fixed_line(case: str) -> None:
    findings = section(render_report(_unverified_models()[case]), 3)
    assert NOT_SHOWN in findings
    assert reproduce_lines(findings) == 0


@pytest.mark.parametrize("verified", [True, False])
def test_fix_snippets_are_static_and_cover_all_five_headers(verified: bool) -> None:
    model = with_excerpt(GOOD) if verified else with_excerpt(CANARY)
    snippets = section(render_report(model), 5)
    assert "Fix snippets" in snippets
    for line in (
        "Content-Security-Policy: default-src 'self'",
        "X-Frame-Options: DENY",
        "X-Content-Type-Options: nosniff",
        "Referrer-Policy: strict-origin-when-cross-origin",
        "Permissions-Policy: camera=()",
    ):
        assert line in snippets
    assert "generic starting points" in snippets
    assert "adapt and test them before deploying" in snippets
    assert "does not count as X-Frame-Options" in snippets
    assert "Retest: Not implemented in Step 1." in snippets
    assert CANARY not in snippets


def test_fix_snippets_do_not_depend_on_the_model() -> None:
    first = section(render_report(with_excerpt(GOOD)), 5)
    second = section(render_report(make_model(CANARY, findings=(), evidence=())), 5)
    assert first == second


def test_remediation_text_also_goes_through_html_escape(monkeypatch: pytest.MonkeyPatch) -> None:
    mark = chr(0x2063)
    monkeypatch.setattr(render_module.html, "escape", lambda value, quote=True: mark + value + mark)
    document = render_report(with_excerpt(excerpt_for(*HEADER_NAMES)))
    nodes = [node for node in _text(document).split("\n") if "How to reproduce" in node]
    assert len(nodes) == len(HEADER_NAMES)
    assert all(node.startswith(mark) and node.endswith(mark) for node in nodes)
