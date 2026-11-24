"""Response helpers: JSON bodies, idempotent replay, and stored-body handling."""
from __future__ import annotations

from typing import Any

from fastapi import Request
from fastapi.responses import JSONResponse, Response

from vulnscope.api.deps import cross_org_miss
from vulnscope.api.idempotency import Conflict, InProgress, Outcome, Replay, Won
from vulnscope.api.limits import MEDIA_TYPE_PROBLEM
from vulnscope.api.logging import log_event
from vulnscope.api.problem import Detail, ProblemError, request_id_of, route_template
from vulnscope.errors import PolicyReasonCode, ReasonCode


def json_response(body: dict[str, Any], status: int = 200,
                  headers: dict[str, str] | None = None) -> JSONResponse:
    return JSONResponse(body, status_code=status, headers=headers)


def replay_response(request: Request, status: int, body: dict[str, Any]) -> Response:
    headers = {"Idempotent-Replayed": "true"}
    if status >= 400:
        out = dict(body)
        out["request_id"] = request_id_of(request)
        return JSONResponse(out, status_code=status, media_type=MEDIA_TYPE_PROBLEM,
                            headers=headers)
    return JSONResponse(body, status_code=status, headers=headers)


def unwrap_outcome(request: Request, outcome: Outcome) -> tuple[str | None, Response | None]:
    """Turn an idempotency outcome into (claim key, None) or (None, replay response); conflicts
    and waits raise the 409."""
    if isinstance(outcome, Won):
        return outcome.key, None
    if isinstance(outcome, Replay):
        return None, replay_response(request, outcome.status, outcome.body)
    headers = {"Retry-After": "1"} if isinstance(outcome, InProgress) else None
    state = getattr(request.app.state, "d", None)
    if state is not None:
        state.counters["idempotency_conflict"] += 1
    log_event("idempotency_conflict", route=route_template(request),
              request_id=request_id_of(request))
    assert isinstance(outcome, Conflict | InProgress)
    raise ProblemError(409, ReasonCode.IDEMPOTENCY_CONFLICT, Detail.IDEMPOTENCY_CONFLICT,
                       headers=headers)


async def missing_logged(request: Request, awaitable: Any) -> Any:
    """Await a scoped lookup; a 404 is logged as a cross-org miss (no ids) and re-raised."""
    try:
        return await awaitable
    except ProblemError as exc:
        if exc.status == 404:
            cross_org_miss(request)
        raise


STORABLE_CODES = (PolicyReasonCode.REVOKED, PolicyReasonCode.EXPIRED)
