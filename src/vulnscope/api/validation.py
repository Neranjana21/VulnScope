"""Pure validation (no I/O): pydantic error mapping, semantic engagement validation, scan request
checks, the best-effort secret scan and field limits (design 7.1, PD-04, PD-05, PD-21).

Nothing derived from the request body (field names, values) is ever copied into a result: paths
come from our own schema vocabulary, and unknown fields are only counted.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from pydantic import BaseModel, ValidationError

from vulnscope.api import limits as L
from vulnscope.api.ports import TargetChecker
from vulnscope.api.problem import Detail, ProblemError
from vulnscope.config import Settings
from vulnscope.errors import ReasonCode
from vulnscope.models.schemas import engagement as eng

# ---- pydantic error mapping -------------------------------------------------------------------
SCHEMA_CODE_ORDER = ("UNKNOWN_FIELD", "WINDOW_NAIVE_DATETIME", "WINDOW_MISSING", "SECRET_INLINE")


def _field_vocabulary() -> frozenset[str]:
    names: set[str] = set()
    for model in (eng.EngagementCreateRequest, eng.Targets, eng.Scope, eng.Window,
                  eng.Authorization, eng.Identity, eng.IdentityAuth, eng.OwnershipRule,
                  eng.AssetTag):
        assert issubclass(model, BaseModel)
        names |= set(model.model_fields)
    return frozenset(names)


_VOCAB = _field_vocabulary()


def _tokens(loc: tuple[Any, ...]) -> list[str]:
    out: list[str] = []
    for part in loc:
        if isinstance(part, int):
            out.append("*")
        elif isinstance(part, str) and part in _VOCAB:
            out.append(part)
        else:
            out.append("?")  # a body-chosen name never reaches a result
    return out


@dataclass
class MappedErrors:
    codes: list[str] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)
    unknown_field_count: int = 0


def map_validation_errors(exc: ValidationError) -> MappedErrors:
    try:
        errors = exc.errors(include_url=False, include_context=False, include_input=False)
    except TypeError:  # keyword absent in this pydantic version: drop the input immediately
        errors = exc.errors(include_url=False, include_context=False)
    found: dict[str, list[str]] = {}
    unknown = 0
    for err in errors[: L.MAX_PYDANTIC_ERRORS_INSPECTED]:
        loc = tuple(err.get("loc", ()))
        etype = str(err.get("type", ""))
        msg = str(err.get("msg", ""))
        code: str | None = None
        path_loc = loc
        if etype == "extra_forbidden":
            code, path_loc = "UNKNOWN_FIELD", loc[:-1]
            unknown += 1
        elif etype == "value_error" and "WINDOW_NAIVE_DATETIME" in msg:
            code = "WINDOW_NAIVE_DATETIME"
        elif etype == "missing" and loc[:2] == ("scope", "window"):
            code = "WINDOW_MISSING"
        elif etype == "string_pattern_mismatch" and loc and loc[-1] == "secret_ref":
            code = "SECRET_INLINE"
        if code is None:
            continue
        path = ".".join(_tokens(path_loc)) or "$"
        paths = found.setdefault(code, [])
        if path not in paths:
            paths.append(path)
    out = MappedErrors(unknown_field_count=unknown)
    for code in SCHEMA_CODE_ORDER:
        if code in found:
            out.codes.append(code)
            out.paths.extend(p for p in found[code] if p not in out.paths)
    return out


# ---- secret scan ------------------------------------------------------------------------------
_SECRET_PATTERNS = [
    re.compile(r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|token|bearer)\b\s*[:=]\s*\S{6,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\."),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"),
]


def has_inline_secret(text: str) -> bool:
    """Best-effort only (a miss is possible; the ledger never holds the text anyway)."""
    return any(p.search(text) for p in _SECRET_PATTERNS)


# ---- limits (phase L) -------------------------------------------------------------------------
def _within(values: list[str], count: int, each: int) -> bool:
    return len(values) <= count and all(len(v) <= each for v in values)


def within_limits(req: eng.EngagementCreateRequest) -> bool:
    if not (1 <= len(req.name) <= L.NAME_MAX):
        return False
    a = req.authorization
    if not (1 <= len(a.approver) <= L.APPROVER_MAX and 1 <= len(a.statement) <= L.STATEMENT_MAX):
        return False
    t, s = req.targets, req.scope
    if len(t.domains) + len(t.ip_ranges) > L.MAX_TARGETS:
        return False
    if not (_within(t.domains, L.MAX_TARGETS, L.SCOPE_ENTRY_MAX)
            and _within(t.ip_ranges, L.MAX_TARGETS, L.SCOPE_ENTRY_MAX)):
        return False
    if t.openapi_url is not None and not (1 <= len(t.openapi_url) <= L.OPENAPI_URL_MAX):
        return False
    for lst in (s.allow, s.deny, s.expected_ip_ranges):
        if not _within(lst, L.SCOPE_LIST_MAX, L.SCOPE_ENTRY_MAX) or any(not x for x in lst):
            return False
    if any(not x for x in (*t.domains, *t.ip_ranges)):
        return False
    if len(req.identities) > L.IDENTITIES_MAX or any(
            not (1 <= len(i.label) <= L.LABEL_MAX and 1 <= len(i.role) <= L.LABEL_MAX
                 and len(i.auth.secret_ref) <= L.SECRET_REF_MAX) for i in req.identities):
        return False
    if len(req.ownership_rules) > L.OWNERSHIP_RULES_MAX or any(
            not (1 <= len(o.resource) <= L.RESOURCE_MAX
                 and 1 <= len(o.owner_identity) <= L.LABEL_MAX) for o in req.ownership_rules):
        return False
    return not (len(req.asset_tags) > L.ASSET_TAGS_MAX or any(
        not (1 <= len(x.match) <= L.SCOPE_ENTRY_MAX and len(x.criticality) <= L.CRITICALITY_MAX
             and len(x.data) <= L.LABEL_MAX) for x in req.asset_tags))


# ---- semantic validation (phase V) ------------------------------------------------------------
@dataclass(frozen=True)
class Violation:
    code: str  # a ReasonCode value, or "INVALID_REQUEST" for a generic (unrecorded) failure
    path: str


def validate_engagement(
    req: eng.EngagementCreateRequest, *, settings: Settings, now: datetime,
    targets: TargetChecker,
) -> list[Violation]:
    s = req.scope
    rps = s.rate_limit_rps
    nb, na = s.window.not_before, s.window.not_after
    if not math.isfinite(rps) or rps <= 0 or nb >= na:
        return [Violation("INVALID_REQUEST", "scope")]
    out: list[Violation] = []
    if req.profile == "lab" and not settings.enable_lab:
        out.append(Violation("PROFILE_NOT_ENABLED", "profile"))
    if not req.authorization.confirmed:
        out.append(Violation("AUTH_NOT_CONFIRMED", "authorization.confirmed"))
    t = req.targets
    no_targets = not t.domains and not t.ip_ranges and not t.openapi_url
    if not s.allow or no_targets:
        out.append(Violation("SCOPE_EMPTY", "scope.allow"))
    if rps > settings.max_rps_per_host:
        out.append(Violation("RATE_ABOVE_CEILING", "scope.rate_limit_rps"))
    if na <= now:
        out.append(Violation("WINDOW_EXPIRED", "scope.window.not_after"))
    if na - nb > timedelta(days=settings.max_window_days):
        out.append(Violation("WINDOW_TOO_LONG", "scope.window"))
    if any(has_inline_secret(x) for x in (req.name, req.authorization.statement,
                                          req.authorization.approver)):
        out.append(Violation("SECRET_INLINE", "authorization"))
    if s.allow and not no_targets:
        findings = targets.check(
            domains=t.domains, ip_ranges=t.ip_ranges, openapi_url=t.openapi_url, allow=s.allow,
            deny=s.deny, expected=s.expected_ip_ranges, profile=req.profile,
            lab_enabled=settings.enable_lab, lab_cidr=settings.lab_cidr)
        for code in ("TARGET_DENIED", "TARGET_NOT_IN_SCOPE"):
            if any(f.code == code for f in findings):
                out.append(Violation(code, "targets"))
    return out


# ---- scan request (PD-21) ---------------------------------------------------------------------
SCAN_STAGES = ("discover", "detect", "validate", "path")


def validate_scan_request(tree: Any) -> list[str]:
    """Check the parsed tree; return the stages. Any problem is a generic 422 (no gate call)."""

    def bad() -> ProblemError:
        return ProblemError(422, ReasonCode.INVALID_REQUEST, Detail.BAD_REQUEST)

    if not isinstance(tree, dict) or set(tree) - {"schema_version", "stages", "options",
                                                   "schedule"}:
        raise bad()
    sv = tree.get("schema_version")
    if sv != 1 or isinstance(sv, bool):
        raise bad()
    opts = tree.get("options", {})
    if not isinstance(opts, dict) or set(opts) - {"write_tests"}:
        raise bad()
    if "write_tests" in opts and opts["write_tests"] is not False:
        raise bad()
    if tree.get("schedule") is not None:
        raise bad()
    stages = tree.get("stages")
    if (not isinstance(stages, list) or not (1 <= len(stages) <= L.MAX_STAGES)
            or any(not isinstance(x, str) or x not in SCAN_STAGES for x in stages)
            or len(set(stages)) != len(stages)):
        raise bad()
    return list(stages)


def validate_revoke_request(tree: Any) -> str:
    if not isinstance(tree, dict) or set(tree) != {"reason"} or not isinstance(tree["reason"], str):
        raise ProblemError(422, ReasonCode.INVALID_REQUEST, Detail.BAD_REQUEST)
    reason: str = tree["reason"]
    if not (1 <= len(reason) <= L.REASON_MAX):
        raise ProblemError(422, ReasonCode.INVALID_REQUEST, Detail.BAD_REQUEST)
    if has_inline_secret(reason):
        raise ProblemError(422, ReasonCode.SECRET_INLINE, Detail.SECRET_INLINE)
    return reason
