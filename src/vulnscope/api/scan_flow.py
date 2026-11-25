"""Scan creation (design 7.2 and Fix rounds 1-2: PD-08, PD-12, PD-13, PD-14, PD-21, PD-22, N-01,
N-06). Every creation attempt makes at least one policy decision; every decision is recorded by the
gate (rule 8). A scan row is inserted ``pending``, the ``scan.created`` entry is appended, then the
row becomes ``queued``: a worker can never see a queued scan without its ledger entry.
"""
from __future__ import annotations

import asyncio
import ipaddress
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from fastapi import Request
from fastapi.responses import Response

from vulnscope.api import ledger_io
from vulnscope.api.auth import Principal
from vulnscope.api.bodies import read_json
from vulnscope.api.db import db_read, db_tx
from vulnscope.api.idempotency import (
    acquire,
    finalize,
    finalize_standalone,
    parse_key_header,
    release,
    request_hash,
)
from vulnscope.api.limits import BODY_CAP_SCAN
from vulnscope.api.logging import log_event
from vulnscope.api.ports import EngagementSnapshot, GateVerdict
from vulnscope.api.problem import Detail, ProblemError, problem_body, route_template
from vulnscope.api.responses import STORABLE_CODES, json_response, missing_logged, unwrap_outcome
from vulnscope.api.revoke_recorder import repair_best_effort
from vulnscope.api.scan_status import transition_scans
from vulnscope.api.scoping import get_engagement, insert_scan, lock_engagement_status
from vulnscope.api.state import AppState
from vulnscope.api.validation import validate_scan_request
from vulnscope.errors import PolicyReasonCode, ReasonCode
from vulnscope.models.schemas.common import uuid7
from vulnscope.models.schemas.scan import ScanCreateResponse

ADAPTER = "api.scan_create"
ADAPTER_LIFECYCLE = "api.scan_create.lifecycle"

_RULE_MAP: dict[str, tuple[int, ReasonCode | PolicyReasonCode, Detail]] = {
    "REVOKED": (409, PolicyReasonCode.REVOKED, Detail.REVOKED),
    "EXPIRED": (409, PolicyReasonCode.EXPIRED, Detail.EXPIRED),
    "NOT_YET_VALID": (409, ReasonCode.TARGET_DENIED, Detail.WINDOW_NOT_OPEN),
    "OUT_OF_SCOPE": (422, ReasonCode.TARGET_NOT_IN_SCOPE, Detail.TARGET_NOT_IN_SCOPE),
    "RATE": (429, ReasonCode.TARGET_DENIED, Detail.RATE_LIMITED),
}
_DENY_422 = ("EXCLUDED", "DENY_ALWAYS_LIST", "DENY_PRIVATE_RANGE", "REDIRECT_DENIED",
             "RESOLVED_OUTSIDE_EXPECTED", "RESOLUTION_FAILED")


@dataclass
class Claim:
    key: str | None = None


@dataclass
class Progress:
    target_index: int = 0
    decisions: int = 0
    range_checks: list[dict[str, object]] = field(default_factory=list)
    lifecycle_probe: bool = False


def deny_error(state: AppState, snap: EngagementSnapshot, verdict: GateVerdict) -> ProblemError:
    rule = verdict.rule_id
    if rule == "OUT_OF_SCOPE" and snap.profile == "lab" and not state.settings.enable_lab:
        return ProblemError(422, ReasonCode.PROFILE_NOT_ENABLED, Detail.PROFILE_NOT_ENABLED,
                            ledger_seq=verdict.ledger_seq)
    if rule in _RULE_MAP:
        status, code, detail = _RULE_MAP[rule]
    else:  # every other rule id, including unknown ones: fail closed
        status, code, detail = 422, ReasonCode.TARGET_DENIED, Detail.TARGET_DENIED
    return ProblemError(status, code, detail, ledger_seq=verdict.ledger_seq)


def _gate_targets(snap: EngagementSnapshot) -> list[str]:
    out = [str(d) for d in snap.targets.get("domains", [])]
    url = snap.targets.get("openapi_url")
    if url:
        parts = urlsplit(str(url))
        if parts.scheme in ("http", "https") and parts.hostname:
            out.append(parts.hostname)
    return out


def _probe_target(snap: EngagementSnapshot) -> str | None:
    ranges = snap.targets.get("ip_ranges", [])
    if not ranges:
        return None
    try:
        return str(ipaddress.ip_network(str(ranges[0]), strict=False).network_address)
    except ValueError:
        return None


async def _gate(state: AppState, snap: EngagementSnapshot, principal: Principal, target: str,
                adapter: str, prog: Progress) -> GateVerdict:
    try:
        verdict = await state.scan_gate.check(
            engagement=snap, target=target, adapter=adapter, actor=principal.actor)
    except Exception as exc:  # noqa: BLE001 - any failure of the gate is a DENY (rule 5, 8)
        await _record_gate_error(state, snap, "exception", type(exc), prog.target_index)
        raise ProblemError(503, ReasonCode.UNAVAILABLE, Detail.UNAVAILABLE,
                           headers={"Retry-After": "1"}) from None
    prog.decisions += 1
    return verdict


async def _record_gate_error(state: AppState, snap: EngagementSnapshot, reason: str,
                             exc_type: type, index: int) -> None:
    log_event("scan_gate_error", reason=reason, engagement_id=snap.id,
              exc_class=f"{exc_type.__module__}.{exc_type.__qualname__}")
    try:
        payload = ledger_io.scan_gate_error(
            state.sanitize, engagement_id=snap.id, reason=reason,
            exc_class=exc_type.__qualname__, target_index=index)
        await state.chain_backend.append(f"engagement:{snap.id}", "scan.gate_error", "system",
                                         payload, state.clock.now())
    except Exception:  # noqa: BLE001 - best effort audit
        log_event("ledger_write_failed", exc_class="scan_gate_error")


async def create_scan(request: Request, state: AppState, principal: Principal,
                      engagement_id: str) -> Response:
    async with db_read(state) as s:
        snap = await missing_logged(request, get_engagement(s, engagement_id, principal.org_id))
    tree = await read_json(request, BODY_CAP_SCAN)
    stages = validate_scan_request(tree)
    key_raw = parse_key_header(request.headers.getlist("idempotency-key"))
    claim = Claim()
    path = f"/v1/engagements/{engagement_id}/scans"
    if key_raw is not None:
        outcome = await acquire(state, org_id=principal.org_id, raw_key=key_raw,
                                rhash=request_hash("POST", path, tree))
        claim.key, replay = unwrap_outcome(request, outcome)
        if replay is not None:
            return replay
    t = state.timeouts
    try:
        permit = await state.gates.org.acquire(principal.org_id)
        deferred = False
        prog = Progress()
        try:
            try:
                async with asyncio.timeout(t.scan_deadline_s):
                    return await _run(request, state, principal, snap, stages, claim, prog)
            except TimeoutError:
                deferred = True  # the resolver thread may still be blocked: hold the slot (N-06)
                permit.release_later(t.resolve_timeout_s + 0.5)
                await _record_gate_error(state, snap, "deadline", TimeoutError, prog.target_index)
                raise ProblemError(503, ReasonCode.UNAVAILABLE, Detail.UNAVAILABLE,
                                   headers={"Retry-After": "1"}) from None
            except ProblemError as exc:
                if claim.key is not None and exc.code in STORABLE_CODES:
                    body = problem_body(status=exc.status, code=exc.code, detail=exc.detail,
                                        instance=route_template(request), request_id=None,
                                        ledger_seq=exc.ledger_seq)
                    if await finalize_standalone(state, claim.key, exc.status, body):
                        claim.key = None
                raise
        finally:
            if not deferred:
                permit.release()
    finally:
        if claim.key is not None:
            await release(state, claim.key)


async def _run(request: Request, state: AppState, principal: Principal,
               snap: EngagementSnapshot, stages: list[str], claim: Claim, prog: Progress
               ) -> Response:
    targets = _gate_targets(snap)
    lifecycle_target: str | None = None
    for idx, target in enumerate(targets):
        prog.target_index = idx
        v = await _gate(state, snap, principal, target, ADAPTER, prog)
        if not v.allowed:
            await _on_deny(state, snap, principal, v)
            raise deny_error(state, snap, v)
    ranges = [str(r) for r in snap.targets.get("ip_ranges", [])]
    if not targets:  # N-01: range-only engagements still get one recorded policy decision
        lifecycle_target = _probe_target(snap)
        if lifecycle_target is None:
            raise await _reject_scan(state, snap, principal, 0, "TARGET_NOT_IN_SCOPE", "no_targets")
        prog.lifecycle_probe = True
        v = await _gate(state, snap, principal, lifecycle_target, ADAPTER_LIFECYCLE, prog)
        if not v.allowed:
            await _on_deny(state, snap, principal, v)
            raise deny_error(state, snap, v)
    s = snap.scope
    for idx, rng in enumerate(ranges):
        prog.target_index = idx
        findings = state.target_checker.check(
            domains=[], ip_ranges=[rng], openapi_url=None, allow=s.get("allow", []),
            deny=s.get("deny", []), expected=s.get("expected_ip_ranges", []),
            profile=snap.profile, lab_enabled=state.settings.enable_lab,
            lab_cidr=state.settings.lab_cidr)
        if findings:
            raise await _reject_scan(state, snap, principal, idx, findings[0].code,
                                     findings[0].rule)
        prog.range_checks.append({"index": idx, "verdict": "allow"})
    first_target = targets[0] if targets else lifecycle_target
    assert first_target is not None
    first_adapter = ADAPTER if targets else ADAPTER_LIFECYCLE
    return await _commit(request, state, principal, snap, stages, claim, prog, first_target,
                         first_adapter)


async def _reject_scan(state: AppState, snap: EngagementSnapshot, principal: Principal,
                       index: int, code: str, rule: str) -> ProblemError:
    payload = ledger_io.scan_rejected(state.sanitize, engagement_id=snap.id, target_index=index,
                                      code=code, rule=rule)
    entry = await ledger_io.append_entry(state, f"engagement:{snap.id}", "scan.rejected",
                                         principal.actor, payload)
    detail = Detail.TARGET_DENIED if code == "TARGET_DENIED" else Detail.TARGET_NOT_IN_SCOPE
    return ProblemError(422, ReasonCode(code), detail, ledger_seq=entry.seq)


async def _on_deny(state: AppState, snap: EngagementSnapshot, principal: Principal,
                   verdict: GateVerdict) -> None:
    if verdict.rule_id == "REVOKED":  # PD-07: repair a revoke whose entry never made it
        async with db_read(state) as s:
            fresh = await get_engagement(s, snap.id, snap.org_id)
        if fresh.status == "revoked":
            await repair_best_effort(state, fresh, principal.actor)


async def _revoked_race(request: Request, state: AppState, principal: Principal,
                        snap: EngagementSnapshot, target: str, adapter: str,
                        prog: Progress) -> ProblemError:
    """A revoke won the race: re-run the gate once so the REVOKED decision is recorded."""
    async with db_read(state) as s:
        fresh = await get_engagement(s, snap.id, snap.org_id)
    v = await _gate(state, fresh, principal, target, adapter, prog)
    if not v.allowed:
        await _on_deny(state, fresh, principal, v)
        return deny_error(state, fresh, v)
    return ProblemError(409, PolicyReasonCode.REVOKED, Detail.REVOKED)


async def _commit(request: Request, state: AppState, principal: Principal,
                  snap: EngagementSnapshot, stages: list[str], claim: Claim, prog: Progress,
                  target: str, adapter: str) -> Response:
    scan_id = uuid7()
    async with db_tx(state) as s:  # T2: serialise against revoke, insert pending
        status = await lock_engagement_status(s, snap.id, principal.org_id)
        active = status == "active"
        if active:
            await insert_scan(s, scan_id=scan_id, org_id=principal.org_id,
                              engagement_id=snap.id, stages=stages, now=state.clock.now())
    if not active:
        raise await _revoked_race(request, state, principal, snap, target, adapter, prog)
    payload = ledger_io.scan_created(
        state.sanitize, scan_id=scan_id, engagement_id=snap.id, stages=stages,
        decision_count=prog.decisions, range_checks=prog.range_checks,
        lifecycle_probe=prog.lifecycle_probe)
    try:
        await ledger_io.append_entry(state, f"engagement:{snap.id}", "scan.created",
                                     principal.actor, payload)
    except BaseException:
        try:
            async with db_tx(state) as s:
                await transition_scans(s, org_id=principal.org_id, to="cancelled",
                                       frm=("pending",), scan_id=scan_id)
        except Exception:  # noqa: BLE001
            log_event("ledger_write_failed", exc_class="scan_cancel")
        raise
    body = ScanCreateResponse(scan_id=scan_id, status="queued").model_dump(mode="json")
    async with db_tx(state) as s:  # T3: pending -> queued (+ claim) in one transaction
        moved = await transition_scans(s, org_id=principal.org_id, to="queued",
                                       frm=("pending",), scan_id=scan_id)
        if moved and claim.key is not None:
            await finalize(s, claim.key, 202, body)
    if not moved:  # a concurrent revoke cancelled the pending row
        raise await _revoked_race(request, state, principal, snap, target, adapter, prog)
    claim.key = None
    return json_response(body, 202)
