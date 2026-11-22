"""The pure decision function (design section 2).

Not exported from ``policy/__init__``: the only production caller is
``decide_and_record`` so that every decision, allow or deny, reaches the ledger.

Order (everything that needs no network runs first; the resolver is called at most
once and only after steps 0-4b pass):
0 input guards; 0b lab configuration; 1 status; 2 window; 2b canonical parse;
3 scope.deny (string); 4b D7 names; 4 scope.allow (string); 5 resolution;
6 D7 addresses (+ embedded IPv4); 7 scope.deny on every resolved IP;
8 private/lab rules on every resolved IP; 9 expected_ip_ranges; 10 rate limit;
11 allow; 12 redirect relabel for denials from steps 3, 4 and 7 only.
"""

from __future__ import annotations

from datetime import UTC, datetime

from vulnscope.policy.clock import Clock
from vulnscope.policy.denylist import match_always_deny_host, match_always_deny_ip_or_embedded
from vulnscope.policy.private_ranges import parse_lab_cidr, private_verdict
from vulnscope.policy.ratelimit import RateLimitStore
from vulnscope.policy.resolver import Resolver
from vulnscope.policy.scope import host_matches, ip_matches
from vulnscope.policy.target import (
    IPAddress,
    TargetParseError,
    canonical_ip,
    canonical_target,
    embedded_ipv4_candidates,
)
from vulnscope.policy.types import (
    ACTION_KINDS,
    Action,
    EngagementPolicyView,
    PolicyDecision,
    RuleId,
)

MAX_RESOLVED = 32


def _resolve(resolver: Resolver, host: str) -> list[IPAddress] | None:
    """One resolution, canonicalised and de-duplicated; None means RESOLUTION_FAILED."""
    try:
        raw = resolver.resolve(host)
    except Exception:  # noqa: BLE001 - any resolver failure is a recorded deny, never a raise
        return None
    if not isinstance(raw, tuple | list) or not raw or len(raw) > MAX_RESOLVED:
        return None
    seen: dict[str, IPAddress] = {}
    for item in raw:
        try:
            ip = canonical_ip(item)
        except (ValueError, TypeError):
            return None
        seen.setdefault(str(ip), ip)
    return list(seen.values())


def decide(
    action: Action,
    engagement: EngagementPolicyView,
    now: datetime,
    *,
    resolver: Resolver,
    clock: Clock,
    rate_limit_store: RateLimitStore,
    lab_enabled: bool = False,
    lab_cidr: str | None = None,
) -> PolicyDecision:
    # Step 0: programming errors raise; hostile target text never does.
    if not isinstance(action.target, str):
        raise TypeError("action.target must be str")
    if action.kind not in ACTION_KINDS:
        raise ValueError("invalid action kind")
    if not isinstance(now, datetime):
        raise TypeError("now must be a datetime")
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
    if lab_cidr is not None and not isinstance(lab_cidr, str):
        raise TypeError("lab_cidr must be str or None")
    ts = now.astimezone(UTC)
    resolved: tuple[str, ...] = ()

    def finish(allowed: bool, rule: RuleId, reason: str) -> PolicyDecision:
        return PolicyDecision(
            allowed=allowed,
            reason=reason,
            rule_id=rule,
            policy_version=engagement.policy_version,
            action=action,
            resolved_ips=resolved,
            ts=ts,
        )

    def deny(rule: RuleId, reason: str) -> PolicyDecision:
        return finish(False, rule, reason)

    def deny_scope(rule: RuleId, reason: str) -> PolicyDecision:
        # Step 12: only denials from steps 3, 4 and 7 are relabelled on a redirect hop.
        return deny(RuleId.REDIRECT_DENIED if action.is_redirect_hop else rule, reason)

    # Step 0b: lab inputs. Never ignored when enabled; ignored entirely when disabled.
    if engagement.profile == "lab" and not lab_enabled:
        return deny(RuleId.OUT_OF_SCOPE, "profile not enabled")
    lab_net = None
    if lab_enabled:
        try:
            lab_net = parse_lab_cidr(lab_cidr)
        except ValueError:
            return deny(RuleId.OUT_OF_SCOPE, "invalid lab configuration")

    # Step 1: status (any value other than "active" fails closed).
    if engagement.status != "active":
        return deny(RuleId.REVOKED, "engagement is not active")
    # Step 2: window, both ends inclusive.
    if now < engagement.window_not_before:
        return deny(RuleId.NOT_YET_VALID, "before the authorized window")
    if now > engagement.window_not_after:
        return deny(RuleId.EXPIRED, "after the authorized window")

    # Step 2b: canonical parse (also rejects empty and over-long text).
    try:
        target = canonical_target(action.target)
    except TargetParseError as exc:
        return deny(RuleId.OUT_OF_SCOPE, f"UNPARSEABLE_TARGET:{exc.code}")

    compiled = engagement.compiled
    # Step 3: exclusions beat inclusions, string level, no network.
    if host_matches(compiled.deny, target):
        return deny_scope(RuleId.EXCLUDED, "target matches scope.deny")
    # Step 4b: D7 names, pure, before any resolution and regardless of scope.allow.
    if target.ip is None:
        name_hit = match_always_deny_host(target.host)
        if name_hit is not None:
            return deny(RuleId.DENY_ALWAYS_LIST, f"name matches always-deny entry {name_hit}")
    # Step 4: coverage by scope.allow (a hostname is not covered by a CIDR entry).
    if not host_matches(compiled.allow, target):
        return deny_scope(RuleId.OUT_OF_SCOPE, "target is not covered by scope.allow")

    # Step 5: the only network action; one resolution per call, IP literals need none.
    ips: list[IPAddress]
    if target.ip is not None:
        ips = [target.ip]
    else:
        looked_up = _resolve(resolver, target.host)
        if looked_up is None:
            return deny(RuleId.RESOLUTION_FAILED, "resolution failed")
        ips = looked_up
    resolved = tuple(str(ip) for ip in ips)

    # Step 6: always-deny addresses on every IP (and embedded IPv4); scope cannot exempt.
    for ip in ips:
        hit = match_always_deny_ip_or_embedded(ip)
        if hit is not None:
            return deny(RuleId.DENY_ALWAYS_LIST, f"address matches always-deny entry {hit}")
    # Step 7: scope.deny on every resolved IP (closes CNAME-into-excluded at IP level).
    for ip in ips:
        if ip_matches(compiled.deny, ip) or any(
            ip_matches(compiled.deny, cand) for cand in embedded_ipv4_candidates(ip)
        ):
            return deny_scope(RuleId.EXCLUDED, "resolved address matches scope.deny")
    # Step 8: private and lab rules on EVERY resolved IP; any failing IP denies.
    for ip in ips:
        verdict = private_verdict(
            ip, profile=engagement.profile, lab_net=lab_net, allow_nets=compiled.allow.nets
        )
        if verdict is not None:
            return deny(verdict[0], verdict[1])
    # Step 9: expected_ip_ranges, when supplied, must contain every resolved IP.
    if compiled.expected.nets and any(not ip_matches(compiled.expected, ip) for ip in ips):
        return deny(
            RuleId.RESOLVED_OUTSIDE_EXPECTED, "resolved address is outside expected_ip_ranges"
        )
    # Step 10: rate limit last, so denied calls never consume tokens.
    key = f"{engagement.engagement_id}:{target.host}"
    if not rate_limit_store.allow(key, engagement.rate_limit_rps, clock.monotonic()):
        return deny(RuleId.RATE, "rate limit exceeded")
    # Step 11.
    return finish(True, RuleId.ALLOW, "allowed")
