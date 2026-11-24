"""Engagement creation flow, phases A (done by the dependency), P, T, K, M, L, V, R, W
(design 0.2, 7.1, 8; PD-04, PD-05, PD-12)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from fastapi import Request
from fastapi.responses import Response
from pydantic import ValidationError

from vulnscope.api import ledger_io
from vulnscope.api.auth import Principal
from vulnscope.api.bodies import read_json
from vulnscope.api.db import db_tx
from vulnscope.api.idempotency import (
    acquire,
    finalize,
    finalize_standalone,
    parse_key_header,
    release,
    request_hash,
)
from vulnscope.api.limits import BODY_CAP_ENGAGEMENT
from vulnscope.api.problem import (
    Detail,
    ProblemError,
    problem_body,
    problem_response,
    request_id_of,
    route_template,
)
from vulnscope.api.responses import json_response, unwrap_outcome
from vulnscope.api.scoping import insert_engagement
from vulnscope.api.state import AppState
from vulnscope.api.validation import map_validation_errors, validate_engagement, within_limits
from vulnscope.errors import ReasonCode
from vulnscope.models.schemas.common import uuid7
from vulnscope.models.schemas.engagement import EngagementCreateRequest, EngagementCreateResponse

PATH = "/v1/engagements"


@dataclass
class Claim:
    key: str | None = None  # None: no claim, or the claim was stored/lost (never release it)


def _generic() -> ProblemError:
    return ProblemError(422, ReasonCode.INVALID_REQUEST, Detail.BAD_REQUEST)


async def create_engagement(request: Request, state: AppState, principal: Principal) -> Response:
    key_raw = parse_key_header(request.headers.getlist("idempotency-key"))
    tree = await read_json(request, BODY_CAP_ENGAGEMENT)
    claim = Claim()
    if key_raw is not None:
        outcome = await acquire(state, org_id=principal.org_id, raw_key=key_raw,
                                rhash=request_hash("POST", PATH, tree))
        claim.key, replay = unwrap_outcome(request, outcome)
        if replay is not None:
            return replay
    try:
        return await _create(request, state, principal, tree, claim)
    finally:
        if claim.key is not None:
            await release(state, claim.key)


async def _reject(request: Request, state: AppState, principal: Principal, claim: Claim, *,
                  codes: list[str], paths: list[str], unknown: int) -> Response:
    payload = ledger_io.engagement_rejected(state.sanitize, codes=codes, paths=paths,
                                            unknown_field_count=unknown)
    entry = await ledger_io.append_entry(state, f"intake:{principal.org_id}",
                                         "engagement.rejected", principal.actor, payload)
    primary = codes[0]
    instance = route_template(request)
    body = problem_body(status=422, code=ReasonCode(primary), detail=Detail[primary],
                        instance=instance, request_id=None, ledger_seq=entry.seq)
    if claim.key is not None:
        if await finalize_standalone(state, claim.key, 422, body):
            claim.key = None
    return problem_response(status=422, code=ReasonCode(primary), detail=Detail[primary],
                            instance=instance, request_id=request_id_of(request),
                            ledger_seq=entry.seq)


async def _create(request: Request, state: AppState, principal: Principal, tree: Any,
                  claim: Claim) -> Response:
    try:  # phase M
        req = EngagementCreateRequest.model_validate(tree)
    except ValidationError as exc:
        mapped = map_validation_errors(exc)
        if not mapped.codes:
            raise _generic() from None
        return await _reject(request, state, principal, claim, codes=mapped.codes,
                             paths=mapped.paths, unknown=mapped.unknown_field_count)
    if not within_limits(req):  # phase L
        raise _generic()
    violations = validate_engagement(  # phase V
        req, settings=state.settings, now=state.clock.now(), targets=state.target_checker)
    if violations:
        if any(v.code == "INVALID_REQUEST" for v in violations):
            raise _generic()
        paths: list[str] = []
        for v in violations:
            if v.path not in paths:
                paths.append(v.path)
        return await _reject(request, state, principal, claim, codes=[v.code for v in violations],
                             paths=paths, unknown=0)
    # phases R and W: the ledger entry first (no FK), then ONE transaction for row + claim
    eid = uuid7()
    payload = ledger_io.engagement_created(state.sanitize, engagement_id=eid, req=req)
    entry = await ledger_io.append_entry(state, f"engagement:{eid}", "engagement.created",
                                         principal.actor, payload)
    now = state.clock.now()
    resp = EngagementCreateResponse(id=eid, status="active", created_at=now,
                                    ledger_seq=entry.seq).model_dump(mode="json")
    async with db_tx(state) as s:
        await insert_engagement(s, engagement_id=eid, org_id=principal.org_id, req=req, now=now)
        if claim.key is not None:
            if not await finalize(s, claim.key, 201, resp):
                claim.key = None  # claimed by someone else now: never release it
                raise ProblemError(409, ReasonCode.IDEMPOTENCY_CONFLICT,
                                   Detail.IDEMPOTENCY_CONFLICT)
    claim.key = None  # stored together with the row (committed)
    return json_response(resp, 201)
