"""Redacted evidence (rule 6). Pure.

The excerpt is assembled ONLY from constants in this module and ``HEADER_NAMES``. The
input is checked against that closed vocabulary and is never copied into the output, and
the error message is fixed, so no target text can pass through here.
"""

from __future__ import annotations

import hashlib

from vulnscope.validate.types import HEADER_NAMES, CheckResult, RedactedEvidence

_INCONCLUSIVE_LINES = {
    "redirect_not_followed": "inconclusive: redirect_not_followed",
    "unexpected_status": "inconclusive: unexpected_status",
}
_REJECTED = "check result is outside the closed vocabulary"


def _excerpt(result: CheckResult) -> str | None:
    """The excerpt, or None if the result is not one ``evaluate`` could have produced."""
    if result.outcome == "inconclusive":
        if result.verdicts or result.reason is None:
            return None
        return _INCONCLUSIVE_LINES.get(result.reason)
    if result.reason is not None or len(result.verdicts) != len(HEADER_NAMES):
        return None
    lines: list[str] = []
    absent = 0
    for expected, (name, verdict) in zip(HEADER_NAMES, result.verdicts, strict=True):
        if name != expected:
            return None
        if verdict == "present":
            lines.append(expected + ": present")
        elif verdict == "absent":
            lines.append(expected + ": absent")
            absent += 1
        else:
            return None
    if result.outcome != ("issue" if absent else "no_issue"):
        return None
    return "\n".join(lines)


def build_evidence(result: CheckResult) -> RedactedEvidence:
    excerpt = _excerpt(result)
    if excerpt is None:
        raise ValueError(_REJECTED)
    return RedactedEvidence(
        excerpt=excerpt, content_sha256=hashlib.sha256(excerpt.encode("utf-8")).hexdigest()
    )
