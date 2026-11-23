"""The single production entry point: decide, then write the decision to the ledger.

Every allow AND deny is appended to the engagement chain (rule 8), and the call fails
closed: any exception, including ``CancelledError`` from ``append``, propagates and no
``PolicyDecision`` is returned, so a caller can never act on an unrecorded allow.

Documented residuals (design 4 and 11.1 RC6):

* ``decide`` runs in a worker thread (``asyncio.to_thread``) so a slow resolver cannot
  stall the event loop. A thread cannot be cancelled: if the awaiting task is cancelled
  mid-resolution, the thread may finish one lookup of an already-authorised name and
  consume one rate token, and NO ledger record is written. The caller still receives
  ``CancelledError`` and no decision, so no action may proceed.
* Append is at-least-once: a lost acknowledgement can leave a duplicate record.
* Exceptions that occur before a decision exists (bad actor, naive ``now``, clock skew,
  policy-version mismatch) write nothing here; the caller (Task D) records a system
  audit entry and fails closed.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
from dataclasses import replace
from datetime import UTC, datetime, timedelta

from vulnscope.ledger.canonical import JsonValue, sanitize_payload
from vulnscope.ledger.chain import ChainBackend
from vulnscope.policy.clock import Clock
from vulnscope.policy.decide import decide
from vulnscope.policy.denylist import compute_policy_version
from vulnscope.policy.private_ranges import parse_lab_cidr
from vulnscope.policy.ratelimit import RateLimitStore
from vulnscope.policy.resolver import Resolver
from vulnscope.policy.target import TargetParseError, canonical_target
from vulnscope.policy.types import Action, AuthorizationBasis, EngagementPolicyView, PolicyDecision

PAYLOAD_SCHEMA_VERSION = 1
MAX_SKEW = timedelta(seconds=60)
RECORD_SKEW = timedelta(seconds=1)
_ACTOR_RE = re.compile(r"system|user:[A-Za-z0-9_-]{1,64}", re.ASCII)


def _iso(ts: datetime) -> str:
    u = ts.astimezone(UTC)
    frac = f".{u.microsecond:06d}" if u.microsecond else ""
    return (
        f"{u.year:04d}-{u.month:02d}-{u.day:02d}T{u.hour:02d}:{u.minute:02d}:{u.second:02d}{frac}Z"
    )


def _lab_cidr_field(lab_enabled: bool, lab_cidr: str | None) -> str | None:
    """Canonical text when enabled and valid, the raw string when enabled and invalid, else None."""
    if not lab_enabled or lab_cidr is None:
        return None
    try:
        net = parse_lab_cidr(lab_cidr)
    except ValueError:
        return lab_cidr  # sanitize_payload caps and escapes it
    return None if net is None else str(net)


def _target_fields(raw: str) -> dict[str, JsonValue]:
    """Rule 6: never store the raw target (userinfo, query and fragment can carry secrets).

    Parseable: canonical scheme, host and port only. Unparseable: a fixed marker and the
    length. Both: the sha256 of the raw string, so the exact input stays attestable.
    """
    digest = hashlib.sha256(raw.encode("utf-8", "surrogatepass")).hexdigest()
    try:
        t = canonical_target(raw)
    except TargetParseError:
        return {"target_unparseable": True, "target_length": len(raw), "target_sha256": digest}
    return {"scheme": t.scheme, "host": t.host, "port": t.port, "target_sha256": digest}


def policy_decision_to_payload(
    decision: PolicyDecision,
    *,
    authorization_basis: AuthorizationBasis | None = None,
    lab_enabled: bool = False,
    lab_cidr: str | None = None,
    clock_ts: datetime | None = None,
) -> dict[str, JsonValue]:
    """Plain-JSON ledger payload; the raw (hostile) target goes in as an ordinary value."""
    basis: dict[str, JsonValue] | None = None
    if authorization_basis is not None:
        basis = {
            "confirmed": authorization_basis.confirmed,
            "approver": authorization_basis.approver,
            "statement_sha256": authorization_basis.statement_sha256,
        }
    action: dict[str, JsonValue] = {
        "kind": decision.action.kind,
        "resolved_ips": list(decision.resolved_ips),
        "adapter": decision.action.adapter,
        "is_redirect_hop": decision.action.is_redirect_hop,
    }
    action.update(_target_fields(decision.action.target))
    payload: dict[str, JsonValue] = {
        "schema_version": PAYLOAD_SCHEMA_VERSION,
        "allowed": decision.allowed,
        "reason": decision.reason,
        "rule_id": decision.rule_id.value,
        "policy_version": decision.policy_version,
        "action": action,
        "ts": _iso(decision.ts),
        "lab_enabled": bool(lab_enabled),
        "lab_cidr": _lab_cidr_field(lab_enabled, lab_cidr),
        "authorization_basis": basis,
    }
    if clock_ts is not None:
        payload["clock_ts"] = _iso(clock_ts)
    return sanitize_payload(payload)


async def decide_and_record(
    action: Action,
    engagement: EngagementPolicyView,
    now: datetime,
    *,
    resolver: Resolver,
    clock: Clock,
    rate_limit_store: RateLimitStore,
    chain_backend: ChainBackend,
    actor: str,
    lab_enabled: bool = False,
    lab_cidr: str | None = None,
) -> PolicyDecision:
    if not isinstance(actor, str) or not _ACTOR_RE.fullmatch(actor):
        raise ValueError("actor must be 'system' or 'user:<id>'")
    if compute_policy_version(lab_enabled=lab_enabled, lab_cidr=lab_cidr) != (
        engagement.policy_version
    ):
        raise ValueError("engagement policy_version does not match the ruleset and lab inputs")
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now must be a timezone-aware datetime")
    wall = clock.now()
    skew = abs(now - wall)
    if skew > MAX_SKEW:
        raise ValueError("now differs from the injected clock by more than 60 seconds")
    clock_ts = wall if skew > RECORD_SKEW else None

    chain_id = f"engagement:{engagement.engagement_id}"
    await chain_backend.head(chain_id)  # preflight: no lookup or token if the ledger is down

    decision = await asyncio.to_thread(
        decide,
        action,
        engagement,
        now,
        resolver=resolver,
        clock=clock,
        rate_limit_store=rate_limit_store,
        lab_enabled=lab_enabled,
        lab_cidr=lab_cidr,
    )
    entry = await chain_backend.append(
        chain_id=chain_id,
        kind="policy.decision",
        actor=actor,
        payload=policy_decision_to_payload(
            decision,
            authorization_basis=engagement.authorization_basis,
            lab_enabled=lab_enabled,
            lab_cidr=lab_cidr,
            clock_ts=clock_ts,
        ),
        ts=decision.ts,
    )
    return replace(decision, ledger_seq=entry.seq)
