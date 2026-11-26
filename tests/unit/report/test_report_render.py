"""The Step 1 HTML report: contract headings, honest limits, and hostile text stays text."""

from __future__ import annotations

import dataclasses
import hashlib
from datetime import UTC, datetime
from html.parser import HTMLParser
from typing import Any

import pytest

from vulnscope.models.schemas.finding import (
    CvssInfo,
    EvidenceView,
    FindingView,
    Priority,
    SourceAdapter,
)
from vulnscope.models.schemas.ledger import VerifyResponse
from vulnscope.report import render as render_module
from vulnscope.report.model import DecisionFact, EngagementFacts, ReportModel
from vulnscope.report.render import LABEL, MAX_REPORT_BYTES, render_report

NOW = datetime(2026, 1, 1, tzinfo=UTC)
EXCERPT = "x-frame-options: absent"
HOSTILE = "\"'><script>alert(1)</script><img src=x onerror=a>&amp;<!--"
HEADINGS = [
    "1 Summary and top fixes",
    "2 Scope, authorization (self-attested), policy used and hosting-verification notes",
    "3 Assets and lifecycle",
    "4 Findings (status, evidence, CVSS v4, priority with reasons and unknown inputs)",
    "5 Attack paths and the recommended fix set (method stated)",
    "6 Fix snippets and retest results",
    "7 Ledger verification result, checkpoint status and limitations",
]
ALLOWED_TAGS = {
    "html", "head", "meta", "title", "body", "h1", "h2", "h3",
    "p", "ul", "li", "table", "tr", "th", "td", "pre", "strong",
}  # fmt: skip


def make_model(t: str = "text", **changes: Any) -> ReportModel:
    """Every free-text field carries ``t``."""
    finding = FindingView(
        id="f1" + t,
        schema_version=1,
        org_id=t,
        engagement_id=t,
        asset_id=t,
        title="title " + t,
        cwe=t,
        taxonomy=[t],
        owasp_api=t,
        status=t,
        severity=None,
        evidence_ids=["ev1" + t],
        cvss=CvssInfo(version="unscored", score=None, vector="", source="none", snapshot="none"),
        priority=Priority(
            band="unscored",
            reasons=[],
            policy_version="none",
            unknown_inputs=["cvss", "kev", "epss", "asset_criticality", "exposure"],
        ),
        source_adapter=SourceAdapter(name=t, version=t),
        first_seen=NOW,
        last_seen=NOW,
    )
    excerpt = EXCERPT + t
    evidence = EvidenceView(
        id="ev1" + t,
        finding_id="f1" + t,
        kind=t,
        redacted_excerpt=excerpt,
        content_sha256=hashlib.sha256(excerpt.encode("utf-8", "surrogatepass")).hexdigest(),
        identity_label=t,
        expected=t,
        observed=t,
        policy_version=t,
        adapter=SourceAdapter(name=t, version=t),
        ledger_chain=t,
        ledger_seq=2,
        created_at=NOW,
    )
    values: dict[str, Any] = {
        "label": LABEL,
        "engagement": EngagementFacts(t, t, t, t, (t,), (t,), t, t, t, t),
        "policy_version": t,
        "decisions": (DecisionFact(0, True, t, t),),
        "findings": (finding,),
        "evidence": (evidence,),
        "evidence_checks": {"ev1" + t: True},
        "outcome": "issue",
        "verify": VerifyResponse(result="ok", first_bad_seq=None, records=4, checkpoint_seq=None),
    }
    values.update(changes)
    return ReportModel(**values)


class Shape(HTMLParser):
    def __init__(self, document: str) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: list[str] = []
        self.attrs: list[tuple[str, str, str | None]] = []
        self.text: list[str] = []
        self.comments: list[str] = []
        self.headings: list[tuple[str, str]] = []
        self._heading: str | None = None
        self.feed(document)
        self.close()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append(tag)
        self.attrs.extend((tag, name, value) for name, value in attrs)
        if tag in ("h2", "h3"):
            self._heading = tag

    def handle_endtag(self, tag: str) -> None:
        self.tags.append("/" + tag)
        self._heading = None

    def handle_data(self, data: str) -> None:
        self.text.append(data)
        if self._heading:
            self.headings.append((self._heading, data))

    def handle_comment(self, data: str) -> None:
        self.comments.append(data)


def _text(document: str) -> str:
    return "\n".join(Shape(document).text)


def test_label_matches_the_required_wording() -> None:
    assert LABEL == "STEP 1 DEVELOPMENT PATH: no gateway, no worker, not the security boundary"
    assert LABEL in _text(render_report(make_model()))


def test_a_model_without_the_exact_label_is_refused() -> None:
    with pytest.raises(ValueError):
        render_report(make_model(label="production assessment"))


def test_contract_headings_in_order_and_limits_section() -> None:
    shape = Shape(render_report(make_model()))
    assert [text for tag, text in shape.headings if tag == "h2"] == HEADINGS
    assert ("h3", "Limits of this assessment") in shape.headings


@pytest.mark.parametrize(
    "phrase",
    [
        "present or absent",
        "frame-ancestors rule does not count as X-Frame-Options",
        "No redirect is followed",
        "no redirect denial (REDIRECT_DENIED) is demonstrated",
        "Revoke is tested only in integration",
        "build configuration only; no wheel was built",
        "not the security boundary and not a Slice 1 result",
        "one HEAD request to our own stub on 127.0.0.1",
        "No egress gateway, worker, queue, job token, process or network isolation",
        "DNS, TLS, redirect following, real labs and real targets are not exercised",
        "Findings are unscored",
        "No checkpoint",
        "GR-SEC-9",
        "SEC-6",
        "bypassed the API",
        "self-attested",
    ],
)
def test_limits_are_stated(phrase: str) -> None:
    limits = _text(render_report(make_model())).split("Limits of this assessment", 1)[1]
    assert phrase in limits


def test_unimplemented_sections_say_so() -> None:
    text = _text(render_report(make_model()))
    for start, end in ((2, 3), (4, 5), (5, 6)):
        section = text.split(HEADINGS[start], 1)[1].split(HEADINGS[end], 1)[0]
        assert "Not implemented in Step 1" in section


def test_unscored_finding_shows_no_number_or_severity() -> None:
    text = _text(render_report(make_model()))
    section = text.split(HEADINGS[3], 1)[1].split(HEADINGS[4], 1)[0]
    assert "unscored" in section
    assert "not assessed" in section
    assert "cvss, kev, epss, asset_criticality, exposure" in section
    assert "0.0" not in section
    assert "None" not in section


def test_scored_finding_shows_score_and_priority_separately() -> None:
    base = make_model()
    scored = base.findings[0].model_copy(
        update={
            "cvss": CvssInfo(version="4.0", score=5.3, vector="V", source="s", snapshot="d"),
            "priority": Priority(band="medium", reasons=["why"], policy_version="1"),
            "severity": "medium",
        }
    )
    text = _text(render_report(dataclasses.replace(base, findings=(scored,))))
    for expected in ("5.3", "medium", "why"):
        assert expected in text


def test_policy_decisions_and_ledger_result_are_shown() -> None:
    model = make_model(
        decisions=(DecisionFact(7, False, "REVOKED", "engagement is not active"),),
        findings=(),
        evidence=(),
        evidence_checks={},
        outcome="revoked",
        verify=VerifyResponse(result="bad_record", first_bad_seq=3, records=9, checkpoint_seq=None),
    )
    text = _text(render_report(model))
    for expected in ("REVOKED", "deny", "bad_record", "revoked", "No findings"):
        assert expected in text
    assert "no checkpoint" in text


def test_evidence_matches_only_if_runner_check_and_recomputed_hash_agree() -> None:
    good = make_model()
    assert "Evidence cross-check: match" in _text(render_report(good))
    failed_check = dataclasses.replace(good, evidence_checks={"ev1text": False})
    unchecked = dataclasses.replace(good, evidence_checks={})
    edited = dataclasses.replace(
        good, evidence=(good.evidence[0].model_copy(update={"redacted_excerpt": "edited"}),)
    )
    for model in (failed_check, unchecked, edited):
        text = _text(render_report(model))
        assert "Evidence cross-check: MISMATCH" in text
        assert "Evidence cross-check: match" not in text


def test_evidence_without_a_listed_finding_is_not_dropped() -> None:
    model = make_model(findings=())
    assert EXCERPT in _text(render_report(model))


def test_document_policy_and_no_active_content() -> None:
    document = render_report(make_model(HOSTILE))
    shape = Shape(document)
    assert document.startswith("<!DOCTYPE html>")
    assert set(shape.tags) <= ALLOWED_TAGS | {"/" + tag for tag in ALLOWED_TAGS}
    assert shape.attrs == [
        ("html", "lang", "en"),
        ("meta", "charset", "utf-8"),
        ("meta", "http-equiv", "Content-Security-Policy"),
        ("meta", "content", "default-src 'none'"),
    ]
    assert shape.comments == []


def test_hostile_text_changes_no_markup_and_stays_visible_as_text() -> None:
    benign = Shape(render_report(make_model("text")))
    document = render_report(make_model(HOSTILE))
    hostile = Shape(document)
    assert (hostile.tags, hostile.attrs) == (benign.tags, benign.attrs)
    assert HOSTILE not in document
    assert "<script" not in document and "<img" not in document
    assert HOSTILE in "".join(hostile.text)


def test_every_text_goes_through_html_escape_with_quote_true(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mark escape's output: every non-blank text node must carry only escaped chunks."""
    calls: list[bool] = []

    def marking(value: str, quote: bool = True) -> str:
        calls.append(quote)
        return "\u2063" + value + "\u2063" if value else value

    monkeypatch.setattr(render_module.html, "escape", marking)
    shape = Shape(render_report(make_model("zz")))
    assert calls and all(calls)
    for node in shape.text:
        if node.strip():
            assert node.startswith("\u2063") and node.endswith("\u2063"), node
    assert all(value and value.startswith("\u2063") for _, _, value in shape.attrs)


def test_control_bidi_and_surrogate_characters_are_replaced() -> None:
    document = render_report(make_model("a\x00\x1b\u202e\u2066\ud800b"))
    for bad in ("\x00", "\x1b", "\u202e", "\u2066", "\ud800"):
        assert bad not in document
    document.encode("utf-8")


def test_long_field_is_truncated_visibly() -> None:
    document = render_report(make_model(decisions=(DecisionFact(0, True, "ALLOW", "r" * 100_000),)))
    assert "[truncated]" in document
    assert len(document.encode()) < 100_000


def test_too_many_items_fail_closed() -> None:
    decision = DecisionFact(0, True, "ALLOW", "allowed")
    with pytest.raises(ValueError, match="size cap"):
        render_report(make_model(decisions=(decision,) * 201))


def test_total_size_cap_fails_closed() -> None:
    assert MAX_REPORT_BYTES == 512 * 1024
    decision = DecisionFact(0, True, "&" * 4096, "&" * 4096)
    with pytest.raises(ValueError, match="size cap"):
        render_report(make_model(decisions=(decision,) * 100))
