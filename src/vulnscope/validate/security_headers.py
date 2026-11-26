"""Literal presence of five response headers. Pure and read-only.

Only header NAMES are looked at. Values are never read, so a weak or empty header counts
as present and an equivalent control elsewhere (CSP ``frame-ancestors``) does not count
(ADR-0013).
"""

from __future__ import annotations

from vulnscope.validate.types import HEADER_NAMES, CheckResult, HeaderResponse


def evaluate(response: HeaderResponse) -> CheckResult:
    """Only a 2xx response can yield an issue. Redirects are not followed."""
    if 300 <= response.status < 400:
        return CheckResult("inconclusive", (), "redirect_not_followed")
    if not 200 <= response.status < 300:
        return CheckResult("inconclusive", (), "unexpected_status")
    # bytes.lower() folds ASCII only; names are compared exactly otherwise.
    seen = {name.lower() for name, _value in response.headers}
    verdicts = tuple(
        (name, "present" if name.encode("ascii") in seen else "absent") for name in HEADER_NAMES
    )
    missing = any(verdict == "absent" for _name, verdict in verdicts)
    return CheckResult("issue" if missing else "no_issue", verdicts, None)  # type: ignore[arg-type]
