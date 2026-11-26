"""STEP 1 DEVELOPMENT PATH report (ADR-0013). Pure, standard library only.

Rule 9: every string in the model is hostile. All markup is built by ``_el``; any child
or attribute value that is not markup built here goes through ``_text``, which caps it,
replaces control, bidi and surrogate characters, and applies ``html.escape(quote=True)``.
No script, link, style or external resource is ever emitted. Over-size input fails
closed with ``ValueError``; items are never silently dropped.
"""

from __future__ import annotations

import hashlib
import html
import unicodedata
from collections.abc import Iterable, Sequence

from vulnscope.models.schemas.finding import EvidenceView, FindingView
from vulnscope.report.model import ReportModel

LABEL = "STEP 1 DEVELOPMENT PATH: no gateway, no worker, not the security boundary"
MAX_REPORT_BYTES = 512 * 1024
MAX_FIELD_CHARS = 4096
MAX_DECISIONS = 200
MAX_FINDINGS = 50
MAX_EVIDENCE = 100
MAX_LIST_ITEMS = 100

_TOO_BIG = "report exceeds the size cap"
_UNSAFE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})
_NOT_IMPLEMENTED = "Not implemented in Step 1."

LIMITS: tuple[str, ...] = (
    "Development path only; not the security boundary and not a Slice 1 result.",
    "It checks five response headers with one HEAD request to our own stub on 127.0.0.1.",
    "Each header is reported only as present or absent, by its literal name. Values are never "
    "judged: a weak, empty or wrong value counts as present. An equivalent control elsewhere is "
    "not recognised: a CSP frame-ancestors rule does not count as X-Frame-Options.",
    "No redirect is followed. A 3xx response is inconclusive and its Location is neither read "
    "nor stored, so no redirect denial (REDIRECT_DENIED) is demonstrated.",
    "Revoke is tested only in integration; it is not part of the demo, and its latency was "
    "not measured.",
    "That the development path is excluded from the built package is shown from the build "
    "configuration only; no wheel was built.",
    "No egress gateway, worker, queue, job token, process or network isolation: enforcement is "
    "in-process code and can be bypassed by a code bug or by other in-process code.",
    "DNS, TLS, redirect following, real labs and real targets are not exercised.",
    "Findings are unscored.",
    "No checkpoint: truncation of the ledger tail or a rewritten chain is undetectable.",
    "The database role can still modify evidence rows and rewind chain heads (GR-SEC-9). "
    "Ledger entries and result rows are not written atomically.",
    "Structural log scrubbing (SEC-6) is absent.",
    "Engagement creation bypassed the API. Authorization is self-attested.",
)


class _Markup(str):
    """HTML produced by this module. Only ``_el`` and ``_text`` create it."""


def _clean(value: str) -> str:
    if len(value) > MAX_FIELD_CHARS:
        value = value[:MAX_FIELD_CHARS] + " [truncated]"
    return "".join(
        "�" if c not in "\n\t" and unicodedata.category(c) in _UNSAFE_CATEGORIES else c
        for c in value
    )


def _text(value: object) -> _Markup:
    return _Markup(html.escape(_clean(str(value)), quote=True))


def _el(tag: str, *children: object, attrs: Sequence[tuple[str, str]] = ()) -> _Markup:
    """``tag`` and attribute names are constants of this module, never model data."""
    opening = tag + "".join(f' {name}="{_text(value)}"' for name, value in attrs)
    if tag == "meta":
        return _Markup(f"<{opening}>")
    inner = "".join(c if type(c) is _Markup else _text(c) for c in children)
    return _Markup(f"<{opening}>{inner}</{tag}>\n")


def _capped[T](items: Sequence[T], limit: int) -> Sequence[T]:
    if len(items) > limit:
        raise ValueError(_TOO_BIG)
    return items


def _joined(items: Sequence[str]) -> str:
    return ", ".join(_capped(items, MAX_LIST_ITEMS)) or "none"


def _or_unstated(value: str | None) -> str:
    return "not stated" if value is None else value


def _bullets(items: Iterable[str]) -> _Markup:
    return _el("ul", *[_el("li", item) for item in items])


def _table(rows: Iterable[tuple[str, object]]) -> _Markup:
    return _el("table", *[_el("tr", _el("th", key), _el("td", value)) for key, value in rows])


def _evidence_block(item: EvidenceView, checks_ok: bool) -> list[_Markup]:
    digest = hashlib.sha256(item.redacted_excerpt.encode("utf-8", "surrogatepass")).hexdigest()
    agrees = checks_ok and digest == item.content_sha256
    return [
        _el("p", _el("strong", "Evidence cross-check: ", "match" if agrees else "MISMATCH")),
        _table(
            [
                ("Evidence id", item.id),
                ("Finding id", item.finding_id),
                ("Kind", item.kind),
                ("Stored content SHA-256", item.content_sha256),
                ("Recomputed excerpt SHA-256", digest),
                ("Identity label", _or_unstated(item.identity_label)),
                ("Expected", _or_unstated(item.expected)),
                ("Observed", _or_unstated(item.observed)),
                ("Policy version", item.policy_version),
                ("Adapter", f"{item.adapter.name} {item.adapter.version}"),
                ("Ledger chain", item.ledger_chain),
                ("Ledger sequence", item.ledger_seq),
                ("Created at", item.created_at.isoformat()),
            ]
        ),
        _el("pre", item.redacted_excerpt),
    ]


def _finding_block(finding: FindingView) -> list[_Markup]:
    cvss, priority = finding.cvss, finding.priority
    return [
        _el("h3", "Finding: ", finding.title),
        _table(
            [
                ("Finding id", finding.id),
                ("Asset id", finding.asset_id),
                ("Status", finding.status),
                ("Severity", "not assessed" if finding.severity is None else finding.severity),
                ("CWE", _or_unstated(finding.cwe)),
                ("Taxonomy", _joined(finding.taxonomy)),
                ("OWASP API", _or_unstated(finding.owasp_api)),
                (
                    "Source adapter",
                    f"{finding.source_adapter.name} " f"{finding.source_adapter.version}",
                ),
                ("First seen", finding.first_seen.isoformat()),
                ("Last seen", finding.last_seen.isoformat()),
            ]
        ),
        _el("p", _el("strong", "CVSS v4")),
        _table(
            [
                ("Version", cvss.version),
                ("Score", "not scored" if cvss.score is None else cvss.score),
                ("Vector", cvss.vector or "none"),
                ("Source", cvss.source),
                ("Snapshot", cvss.snapshot),
            ]
        ),
        _el("p", _el("strong", "Priority")),
        _table(
            [
                ("Band", priority.band),
                ("Reasons", _joined(priority.reasons)),
                ("Priority policy version", priority.policy_version),
                ("Unknown inputs", _joined(priority.unknown_inputs)),
            ]
        ),
    ]


def _findings_section(model: ReportModel) -> list[_Markup]:
    findings = _capped(model.findings, MAX_FINDINGS)
    evidence = _capped(model.evidence, MAX_EVIDENCE)
    parts: list[_Markup] = [] if findings else [_el("p", "No findings.")]
    for finding in findings:
        parts += _finding_block(finding)
        for item in evidence:
            if item.finding_id == finding.id:
                parts += _evidence_block(item, model.evidence_checks.get(item.id) is True)
    listed = {finding.id for finding in findings}
    orphans = [item for item in evidence if item.finding_id not in listed]
    if orphans:
        parts.append(_el("h3", "Evidence not linked to a listed finding"))
        for item in orphans:
            parts += _evidence_block(item, model.evidence_checks.get(item.id) is True)
    return parts


def _scope_section(model: ReportModel) -> list[_Markup]:
    facts = model.engagement
    decisions = _capped(model.decisions, MAX_DECISIONS)
    rows = [_el("tr", *[_el("th", h) for h in ("Ledger sequence", "Decision", "Rule", "Reason")])]
    rows += [
        _el(
            "tr",
            *[
                _el("td", cell)
                for cell in (d.ledger_seq, "allow" if d.allowed else "deny", d.rule_id, d.reason)
            ],
        )
        for d in decisions
    ]
    return [
        _table(
            [
                ("Engagement id", facts.engagement_id),
                ("Organisation id", facts.org_id),
                ("Profile", facts.profile),
                ("Status", facts.status),
                ("Scope allow", _joined(facts.scope_allow)),
                ("Scope deny", _joined(facts.scope_deny)),
                ("Window not before", facts.window_not_before),
                ("Window not after", facts.window_not_after),
                ("Approver (self-attested)", facts.approver),
                ("Authorization statement SHA-256", facts.statement_sha256),
                ("Policy version", model.policy_version),
            ]
        ),
        _el("p", "Hosting verification: not performed in Step 1."),
        _el("h3", "Policy decisions"),
        _el("table", *rows),
    ]


def _ledger_section(model: ReportModel) -> list[_Markup]:
    verify = model.verify
    checkpoint = (
        "no checkpoint (not verified against one)"
        if verify.checkpoint_seq is None
        else verify.checkpoint_seq
    )
    return [
        _table(
            [
                ("Verification result", verify.result),
                ("Records", verify.records),
                (
                    "First bad sequence",
                    "none" if verify.first_bad_seq is None else verify.first_bad_seq,
                ),
                ("Checkpoint status", checkpoint),
            ]
        ),
        _el("h3", "Limits of this assessment"),
        _bullets(LIMITS),
    ]


def render_report(model: ReportModel) -> str:
    if model.label != LABEL:
        raise ValueError("report model does not carry the Step 1 label")
    sections: list[tuple[str, list[_Markup]]] = [
        (
            "1 Summary and top fixes",
            [
                _el("p", "Outcome: ", model.outcome),
                _el("p", "Findings listed: ", len(model.findings)),
                _el("p", "Top fixes: ", _NOT_IMPLEMENTED),
            ],
        ),
        (
            "2 Scope, authorization (self-attested), policy used and hosting-verification notes",
            _scope_section(model),
        ),
        (
            "3 Assets and lifecycle",
            [_el("p", _NOT_IMPLEMENTED, " There is no asset inventory or lifecycle.")],
        ),
        (
            "4 Findings (status, evidence, CVSS v4, priority with reasons and unknown inputs)",
            _findings_section(model),
        ),
        (
            "5 Attack paths and the recommended fix set (method stated)",
            [_el("p", _NOT_IMPLEMENTED, " No paths, fix set or method.")],
        ),
        ("6 Fix snippets and retest results", [_el("p", _NOT_IMPLEMENTED)]),
        ("7 Ledger verification result, checkpoint status and limitations", _ledger_section(model)),
    ]
    head = _el(
        "head",
        _el("meta", attrs=[("charset", "utf-8")]),
        _el(
            "meta",
            attrs=[("http-equiv", "Content-Security-Policy"), ("content", "default-src 'none'")],
        ),
        _el("title", LABEL),
    )
    body: list[_Markup] = [_el("h1", "VulnScope report"), _el("p", _el("strong", LABEL))]
    for heading, parts in sections:
        body.append(_el("h2", heading))
        body += parts
    document = "<!DOCTYPE html>\n" + _el("html", head, _el("body", *body), attrs=[("lang", "en")])
    if len(document.encode("utf-8")) > MAX_REPORT_BYTES:
        raise ValueError(_TOO_BIG)
    return document
