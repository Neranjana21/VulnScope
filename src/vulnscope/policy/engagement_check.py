"""Pure string-level engagement validation (design 11.4, obligation to Task D).

``validate_engagement_targets`` is what Task D's engagement-creation validation
calls so that D never carries a second parser or matcher. It is NOT an
authorisation: it resolves nothing, produces no ``PolicyDecision`` and a clean
result must never be stored as an approval. Scan-time ``decide_and_record``
stays the only gate (a name that resolves into a private or excluded range is
caught there, not here).

Pure and total on hostile text: no network, no ledger, no environment, no clock,
no module state. Every hostile STRING yields an issue and never an exception;
non-``str`` entries, non-sequence arguments and an unknown profile are
programming errors (``TypeError``). Issues carry a field path, an index, a
verdict and a closed rule and code; they never contain input text.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from vulnscope.policy.denylist import (
    ALWAYS_DENY_NETWORKS,
    match_always_deny_host,
    match_always_deny_ip_or_embedded,
    network_overlaps_always_deny,
)
from vulnscope.policy.private_ranges import (
    LOOPBACK,
    PRIVATE_BLOCKS,
    in_any,
    is_private_opt_in_net,
    parse_lab_cidr,
    private_verdict,
    subnet_of,
)
from vulnscope.policy.scope import (
    MAX_ENTRIES,
    CompiledScope,
    ScopeEntryError,
    compile_scope,
    host_matches,
    ip_matches,
)
from vulnscope.policy.target import (
    IPNetwork,
    TargetParseError,
    canonical_target,
    embedded_ipv4_candidates,
    embedded_ipv4_networks,
)
from vulnscope.policy.types import RuleId

type Field = Literal[
    "scope.allow",
    "scope.deny",
    "scope.expected_ip_ranges",
    "targets.domains",
    "targets.ip_ranges",
    "profile",
]
type Verdict = Literal["denied", "not_in_scope", "invalid"]
type Rule = Literal[
    "ALWAYS_DENY", "SCOPE_DENY", "PRIVATE_RANGE", "LAB", "NOT_COVERED", "SYNTAX", "LIMIT"
]


@dataclass(frozen=True)
class ScopeIssue:
    field: Field
    index: int  # position in that list; -1 = list-level or profile-level
    verdict: Verdict
    rule: Rule
    code: str  # closed ASCII vocabulary; never echoes input


def _issue(field: Field, index: int, verdict: Verdict, rule: Rule, code: str) -> ScopeIssue:
    return ScopeIssue(field, index, verdict, rule, code)


def _require_strings(name: str, value: Sequence[str]) -> None:
    if isinstance(value, str | bytes) or not isinstance(value, Sequence):
        raise TypeError(f"{name} must be a sequence of str")
    for item in value:
        if not isinstance(item, str):
            raise TypeError(f"{name} entries must be str")


def _scope_list(
    field: Field,
    entries: Sequence[str],
    kind: Literal["allow", "deny", "expected"],
    issues: list[ScopeIssue],
) -> tuple[CompiledScope | None, bool]:
    """Returns (compiled list or None when unusable, had_blocking_issue)."""
    if len(entries) > MAX_ENTRIES:
        issues.append(_issue(field, -1, "invalid", "LIMIT", "TOO_MANY"))
        return None, True
    good: list[str] = []
    blocking = False
    for i, entry in enumerate(entries):
        try:
            compiled = compile_scope([entry], kind)
        except ScopeEntryError as exc:
            issues.append(_issue(field, i, "invalid", "SYNTAX", f"ENTRY:{exc.code}"))
            blocking = True
            continue
        good.append(entry)
        if kind == "allow" and _allow_entry_is_always_denied(compiled):
            issues.append(_issue(field, i, "denied", "ALWAYS_DENY", "ALLOW_ENTRY_DENIED"))
    if blocking:
        return None, True
    return compile_scope(good, kind), False


def _allow_entry_is_always_denied(compiled: CompiledScope) -> bool:
    """True when an allow entry lies WHOLLY inside always-deny space (dead config)."""
    for net in compiled.nets:
        if any(subnet_of(net, deny) for deny in ALWAYS_DENY_NETWORKS):
            return True
    if any(match_always_deny_host(h) for h in compiled.exact_hosts):
        return True
    return any(match_always_deny_host(s) for s in compiled.wildcard_suffixes)


def _deny_overlaps(net: IPNetwork, deny: CompiledScope) -> bool:
    projections = embedded_ipv4_networks(net)
    for d in deny.nets:
        if d.version == net.version and net.overlaps(d):
            return True
        if any(p.version == d.version and p.overlaps(d) for p in projections):
            return True
    return False


def _check_domain(
    text: str,
    index: int,
    *,
    allow: CompiledScope,
    deny: CompiledScope,
    profile: Literal["standard", "lab"],
    lab_net: IPNetwork | None,
) -> ScopeIssue | None:
    field: Field = "targets.domains"
    try:
        target = canonical_target(text)
    except TargetParseError as exc:
        return _issue(field, index, "invalid", "SYNTAX", f"PARSE:{exc.code}")
    ip = target.ip
    if ip is None:
        if match_always_deny_host(target.host) is not None:
            return _issue(field, index, "denied", "ALWAYS_DENY", "NAME")
    elif match_always_deny_ip_or_embedded(ip) is not None:
        return _issue(field, index, "denied", "ALWAYS_DENY", "HOST")
    if host_matches(deny, target) or (
        ip is not None and any(ip_matches(deny, c) for c in embedded_ipv4_candidates(ip))
    ):
        return _issue(field, index, "denied", "SCOPE_DENY", "HOST")
    if ip is not None:
        verdict = private_verdict(ip, profile=profile, lab_net=lab_net, allow_nets=allow.nets)
        if verdict is not None:
            if verdict[0] == RuleId.DENY_PRIVATE_RANGE:
                code = "LOOPBACK" if in_any(ip, LOOPBACK) else "NO_OPT_IN"
                return _issue(field, index, "denied", "PRIVATE_RANGE", code)
            return _issue(field, index, "denied", "LAB", "OUTSIDE_LAB")
    if not host_matches(allow, target):
        return _issue(field, index, "not_in_scope", "NOT_COVERED", "HOST")
    return None


def _check_range(
    text: str,
    index: int,
    *,
    allow: CompiledScope,
    deny: CompiledScope,
    profile: Literal["standard", "lab"],
    lab_net: IPNetwork | None,
) -> ScopeIssue | None:
    field: Field = "targets.ip_ranges"
    try:
        net = compile_scope([text], "expected").nets[0]
    except ScopeEntryError as exc:
        return _issue(field, index, "invalid", "SYNTAX", f"ENTRY:{exc.code}")
    if network_overlaps_always_deny(net) or any(
        network_overlaps_always_deny(p) for p in embedded_ipv4_networks(net)
    ):
        return _issue(field, index, "denied", "ALWAYS_DENY", "RANGE_OVERLAP")
    if _deny_overlaps(net, deny):
        return _issue(field, index, "denied", "SCOPE_DENY", "RANGE_OVERLAP")
    if profile == "lab":
        allowed_lab = (*LOOPBACK, *((lab_net,) if lab_net is not None else ()))
        if not any(subnet_of(net, base) for base in allowed_lab):
            return _issue(field, index, "denied", "LAB", "OUTSIDE_LAB")
    else:
        if any(net.version == b.version and net.overlaps(b) for b in LOOPBACK):
            return _issue(field, index, "denied", "PRIVATE_RANGE", "LOOPBACK")
        if any(net.version == b.version and net.overlaps(b) for b in PRIVATE_BLOCKS):
            if not any(is_private_opt_in_net(a) and subnet_of(net, a) for a in allow.nets):
                return _issue(field, index, "denied", "PRIVATE_RANGE", "NO_OPT_IN")
    same_family = [a for a in allow.nets if a.version == net.version]
    covering = ipaddress.collapse_addresses(same_family) if same_family else ()  # type: ignore[type-var]
    if not any(subnet_of(net, c) for c in covering):
        return _issue(field, index, "not_in_scope", "NOT_COVERED", "RANGE")
    return None


def validate_engagement_targets(
    *,
    domains: Sequence[str],
    ip_ranges: Sequence[str],
    allow: Sequence[str],
    deny: Sequence[str],
    expected_ip_ranges: Sequence[str],
    profile: Literal["standard", "lab"],
    lab_enabled: bool = False,
    lab_cidr: str | None = None,
) -> tuple[ScopeIssue, ...]:
    for name, value in (
        ("domains", domains),
        ("ip_ranges", ip_ranges),
        ("allow", allow),
        ("deny", deny),
        ("expected_ip_ranges", expected_ip_ranges),
    ):
        _require_strings(name, value)
    if profile not in ("standard", "lab"):
        raise TypeError("profile must be 'standard' or 'lab'")
    if lab_cidr is not None and not isinstance(lab_cidr, str):
        raise TypeError("lab_cidr must be str or None")

    issues: list[ScopeIssue] = []
    allow_c, allow_blocked = _scope_list("scope.allow", allow, "allow", issues)
    deny_c, deny_blocked = _scope_list("scope.deny", deny, "deny", issues)
    _, expected_blocked = _scope_list(
        "scope.expected_ip_ranges", expected_ip_ranges, "expected", issues
    )

    lab_net: IPNetwork | None = None
    if profile == "lab" and not lab_enabled:
        issues.append(_issue("profile", -1, "denied", "LAB", "PROFILE_NOT_ENABLED"))
    elif lab_enabled:
        try:
            lab_net = parse_lab_cidr(lab_cidr)
        except ValueError:
            issues.append(_issue("profile", -1, "invalid", "LAB", "LAB_CONFIG"))

    if allow_blocked or deny_blocked or expected_blocked or allow_c is None or deny_c is None:
        return tuple(issues)

    for field, entries in (("targets.domains", domains), ("targets.ip_ranges", ip_ranges)):
        if len(entries) > MAX_ENTRIES:
            issues.append(_issue(field, -1, "invalid", "LIMIT", "TOO_MANY"))  # type: ignore[arg-type]
            continue
        for i, text in enumerate(entries):
            checker = _check_domain if field == "targets.domains" else _check_range
            found = checker(text, i, allow=allow_c, deny=deny_c, profile=profile, lab_net=lab_net)
            if found is not None:
                issues.append(found)
    return tuple(issues)
