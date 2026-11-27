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
from vulnscope.report.model import ReportModel, TargetKind
from vulnscope.validate.types import HEADER_NAMES, HeaderName

LABEL = "STEP 1 DEVELOPMENT PATH: no gateway, no worker, not the security boundary"
MAX_REPORT_BYTES = 512 * 1024
MAX_FIELD_CHARS = 4096
MAX_DECISIONS = 200
MAX_FINDINGS = 50
MAX_EVIDENCE = 100
MAX_LIST_ITEMS = 100
MAX_PROBLEMS = 500
_CHECK_WORDS = {"ok": "ok", "mismatch": "MISMATCH", "incomplete": "check incomplete"}

_TOO_BIG = "report exceeds the size cap"
_UNSAFE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})
_NOT_IMPLEMENTED = "Not implemented in Step 1."

# Constants of this module, never target data.
_NOT_VERIFIED = "remediation not shown: evidence could not be verified"
_NONE_ABSENT = "The verified evidence marks no header as absent."
_PRESENCE_ONLY = (
    "This check is presence-only. Adding a header changes its result but does not show that "
    "the value is safe or that the site is secure."
)
_REMEDIATION: dict[HeaderName, str] = {
    "content-security-policy": (
        "Send a Content-Security-Policy header that allows only the sources the application "
        "needs. A Content-Security-Policy-Report-Only header helps with testing a policy, but "
        "it does not enforce it and this check does not count it."
    ),
    "x-frame-options": (
        "Send X-Frame-Options with DENY, or SAMEORIGIN if the application frames its own "
        "pages. A CSP frame-ancestors rule is also worth setting, but a CSP frame-ancestors "
        "rule does not count as X-Frame-Options for this check."
    ),
    "x-content-type-options": (
        "Send X-Content-Type-Options with nosniff, and check that every response declares the "
        "correct Content-Type."
    ),
    "referrer-policy": (
        "Send a Referrer-Policy that limits what is shared with other sites, for example "
        "strict-origin-when-cross-origin, or no-referrer if no referrer is needed."
    ),
    "permissions-policy": (
        "Send a Permissions-Policy that turns off browser features the application does not "
        "use, for example camera, microphone and geolocation. Browser support varies."
    ),
}
_SNIPPETS: dict[HeaderName, str] = {
    "content-security-policy": (
        "Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'self'; "
        "frame-ancestors 'none'"
    ),
    "x-frame-options": "X-Frame-Options: DENY",
    "x-content-type-options": "X-Content-Type-Options: nosniff",
    "referrer-policy": "Referrer-Policy: strict-origin-when-cross-origin",
    "permissions-policy": "Permissions-Policy: camera=(), microphone=(), geolocation=()",
}
_SNIPPET_CAUTION = (
    "These are static, generic starting points, not generated from the target. They can break "
    "an application, so adapt and test them before deploying. The check is presence-only: a "
    "snippet does not make a site secure. The frame-ancestors rule in the first snippet does "
    "not count as X-Frame-Options for this check."
)

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
    "The database role can still modify evidence rows, delete finding and evidence rows, and "
    "rewind chain heads (GR-SEC-9). Ledger entries and result rows are not written atomically.",
    "Engagement status and window are read again from the database just before the request. A "
    "revoke or window expiry that happens after that re-read and before the request bytes are on "
    "the wire is not prevented: the in-flight watcher may cancel too late. A request refused by "
    "the re-read leaves an allow decision in the ledger with nothing sent. No separate entry "
    "records the refusal. This is accepted for the development spike only (backlog "
    "BL-S1-F9: record the abort when Step 2 lands).",
    "The report-level check compares ledger entries and result rows in both directions for this "
    "engagement. Compared with the ledger: evidence content hash, ids, policy version, adapter "
    "and finding status. Compared with fixed constants in this code, because the ledger does not "
    "record them: evidence kind, expected and observed text, and finding title. Other fields (for "
    "example severity, CVSS, priority, asset id, taxonomy, identity label and timestamps) are "
    "not compared. An unverified, short or over-bound ledger read is reported as incomplete.",
    "Structural log scrubbing (SEC-6) is absent.",
    "Engagement creation bypassed the API. Authorization is self-attested.",
)

# The lab app limits (ADR-0014): the stub sentences that would be false are replaced.
_LAB_REPLACED: dict[str, str] = {
    LIMITS[1]: (
        "It checks five response headers with one HEAD request to the lab app on "
        "127.0.0.1:3000. It is meant only for a deliberately vulnerable lab app that the "
        "operator runs locally."
    ),
    LIMITS[4]: (
        "Revoke is tested only in integration; neither command demonstrates it, and its "
        "latency was not measured."
    ),
    LIMITS[7]: (
        "DNS, TLS, redirect following and real targets are not exercised. The only request "
        "is the header presence check."
    ),
}
_LAB_ADDED: tuple[str, ...] = (
    "Port 3000 cannot identify Juice Shop: the sender cannot verify that whatever listens "
    "there is Juice Shop. It could be any other local server, such as your own development "
    "server. The operator attests it.",
    "Container and network settings used for the lab are lab hygiene, not the worker "
    "boundary: lab isolation not verified.",
    "Only the presence of the five header names is checked, as one boolean each. Cookies, "
    "server banners, paths other than /, GET requests and response bodies are not examined.",
    "SEC-6 and GR-SEC-9 remain open while a lab app's responses are read.",
)
LAB_APP_LIMITS: tuple[str, ...] = (
    tuple(_LAB_REPLACED.get(item, item) for item in LIMITS) + _LAB_ADDED
)
_LIMITS_BY_KIND: dict[TargetKind, tuple[str, ...]] = {
    "own_stub": LIMITS,
    "lab_app": LAB_APP_LIMITS,
}
# (text before the header name, text after it) of the reproduce line.
_REPRODUCE: dict[TargetKind, tuple[str, str]] = {
    "own_stub": (
        "How to reproduce: HEAD / was sent to the demo's own local stub on 127.0.0.1; "
        "the response had no ",
        " header. The stub is temporary, so to reproduce this, run the demo again.",
    ),
    "lab_app": (
        "How to reproduce: HEAD / was sent to the lab app on 127.0.0.1:3000; "
        "the response had no ",
        " header. The sender cannot verify that the app is Juice Shop. To reproduce this, "
        "run devpath.step1b again with the same app listening.",
    ),
}


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


def _digest(item: EvidenceView) -> str:
    return hashlib.sha256(item.redacted_excerpt.encode("utf-8", "surrogatepass")).hexdigest()


def _agrees(model: ReportModel, item: EvidenceView) -> bool:
    """The runner's check and the hash recomputed here must both agree."""
    return model.evidence_checks.get(item.id) is True and _digest(item) == item.content_sha256


def _parse_absent(excerpt: str) -> tuple[HeaderName, ...] | None:
    """Exactly one ``name: absent|present`` line per allowlisted name, in order, else None.

    The names returned are this code's constants; no excerpt text is passed on.
    """
    lines = excerpt.split("\n")
    if len(lines) != len(HEADER_NAMES):
        return None
    absent: list[HeaderName] = []
    for name, line in zip(HEADER_NAMES, lines, strict=True):
        if line == name + ": absent":
            absent.append(name)
        elif line != name + ": present":
            return None
    return tuple(absent)


def _verified_absent(model: ReportModel, finding: FindingView) -> tuple[HeaderName, ...] | None:
    """None unless every part of this finding's evidence can be relied on (fail closed).

    Any report-level problem suppresses every finding: a problem may name a ledger payload
    id, so it cannot safely be pinned to one finding.
    """
    if model.integrity.status != "ok":
        return None
    linked = [item for item in model.evidence if item.finding_id == finding.id]
    if sorted(item.id for item in linked) != sorted(finding.evidence_ids):
        return None
    if not all(_agrees(model, item) for item in linked):
        return None
    parsed = {_parse_absent(item.redacted_excerpt) for item in linked}
    return parsed.pop() if len(parsed) == 1 else None


def _remediation_block(model: ReportModel, finding: FindingView) -> list[_Markup]:
    parts = [_el("p", _el("strong", "Remediation"))]
    absent = _verified_absent(model, finding)
    if absent is None:
        return [*parts, _el("p", _NOT_VERIFIED)]
    if not absent:
        return [*parts, _el("p", _NONE_ABSENT)]
    parts.append(_el("p", _PRESENCE_ONLY))
    before, after = _REPRODUCE[model.target_kind]
    for name in absent:
        parts += [
            _el("p", _el("strong", "Absent header: ", name)),
            _el("p", _REMEDIATION[name]),
            _el("p", before, name, after),
        ]
    return parts


def _snippets_section() -> list[_Markup]:
    parts = [_el("h3", "Fix snippets"), _el("p", _SNIPPET_CAUTION)]
    for name in HEADER_NAMES:
        parts += [_el("p", _el("strong", name)), _el("pre", _SNIPPETS[name])]
    parts.append(_el("p", "Retest: ", _NOT_IMPLEMENTED))
    return parts


def _evidence_block(model: ReportModel, item: EvidenceView) -> list[_Markup]:
    return [
        _el(
            "p",
            _el(
                "strong", "Evidence cross-check: ", "match" if _agrees(model, item) else "MISMATCH"
            ),
        ),
        _table(
            [
                ("Evidence id", item.id),
                ("Finding id", item.finding_id),
                ("Kind", item.kind),
                ("Stored content SHA-256", item.content_sha256),
                ("Recomputed excerpt SHA-256", _digest(item)),
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


def _integrity_line(model: ReportModel) -> _Markup:
    word = _CHECK_WORDS[model.integrity.status]
    return _el("p", _el("strong", "Report-level ledger and row check: ", word))


def _integrity_block(model: ReportModel) -> list[_Markup]:
    """Independent of the listed rows, so it shows even when every row is gone."""
    check = model.integrity
    parts = [_integrity_line(model)]
    if check.incomplete_reasons:
        parts.append(_el("p", "Incomplete because: ", _joined(check.incomplete_reasons)))
    problems = _capped(check.problems, MAX_PROBLEMS)
    if problems:
        parts.append(_el("p", "MISMATCH between the ledger and the result rows:"))
        rows = [_el("tr", _el("th", "Problem"), _el("th", "Record id"))]
        rows += [_el("tr", _el("td", p.code), _el("td", p.record_id)) for p in problems]
        parts.append(_el("table", *rows))
    return parts


def _findings_section(model: ReportModel) -> list[_Markup]:
    findings = _capped(model.findings, MAX_FINDINGS)
    evidence = _capped(model.evidence, MAX_EVIDENCE)
    parts = _integrity_block(model)
    if not findings:
        parts.append(_el("p", "No findings."))
    for finding in findings:
        parts += _finding_block(finding)
        for item in evidence:
            if item.finding_id == finding.id:
                parts += _evidence_block(model, item)
        parts += _remediation_block(model, finding)
    listed = {finding.id for finding in findings}
    orphans = [item for item in evidence if item.finding_id not in listed]
    if orphans:
        parts.append(_el("h3", "Evidence not linked to a listed finding"))
        for item in orphans:
            parts += _evidence_block(model, item)
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
        _bullets(_LIMITS_BY_KIND[model.target_kind]),
    ]


def render_report(model: ReportModel) -> str:
    if model.label != LABEL:
        raise ValueError("report model does not carry the Step 1 label")
    if model.target_kind not in _LIMITS_BY_KIND:
        raise ValueError("report model has an unknown target kind")
    sections: list[tuple[str, list[_Markup]]] = [
        (
            "1 Summary and top fixes",
            [
                _el("p", "Outcome: ", model.outcome),
                _integrity_line(model),
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
        ("6 Fix snippets and retest results", _snippets_section()),
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
