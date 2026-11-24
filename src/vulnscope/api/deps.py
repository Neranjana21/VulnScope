"""Request dependencies: state access, authentication, role checks (PD-09, PD-10, PD-19).

Authentication and the role check complete before any handler reads a body. Nothing here has a
yield dependency: handlers open short sessions themselves, so no connection is held across a
ledger call or after the response."""
from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import NoReturn

from fastapi import Depends, Request
from sqlalchemy.exc import TimeoutError as SaTimeoutError

from vulnscope.api.auth import Principal, Role, authenticate, parse_bearer
from vulnscope.api.logging import log_event
from vulnscope.api.problem import Detail, ProblemError, request_id_of, route_template
from vulnscope.api.state import AppState
from vulnscope.errors import ReasonCode

REVOKE_ROUTE = "/v1/engagements/{id}/revoke"


def get_state(request: Request) -> AppState:
    state = getattr(request.app.state, "d", None)
    if not isinstance(state, AppState):
        raise ProblemError(503, ReasonCode.UNAVAILABLE, Detail.UNAVAILABLE,
                           headers={"Retry-After": "1"})
    return state


def count(request: Request, event: str) -> None:
    state = getattr(request.app.state, "d", None)
    if isinstance(state, AppState):
        state.counters[event] += 1


def _unauthenticated(request: Request, reason: str) -> NoReturn:
    state = getattr(request.app.state, "d", None)
    count(request, "auth_failed")
    if not isinstance(state, AppState) or state.auth_log.allow():
        suppressed = state.auth_log.take_suppressed() if isinstance(state, AppState) else 0
        log_event("auth_failed", reason=reason, request_id=request_id_of(request),
                  route=route_template(request), suppressed=suppressed or None)
    raise ProblemError(401, ReasonCode.UNAUTHENTICATED, Detail.UNAUTHENTICATED,
                       headers={"WWW-Authenticate": "Bearer"})


async def current_principal(request: Request) -> Principal:
    header = request.headers.get("authorization")
    raw = parse_bearer(header)
    if raw is None:
        _unauthenticated(request, "missing" if header is None else "malformed")
    state = get_state(request)
    t = state.timeouts
    reserved_ok = (request.method == "POST" and route_template(request) == REVOKE_ROUTE)
    principal: Principal | None
    try:
        async with state.gates.auth.slot(reserved_ok=reserved_ok):
            async with asyncio.timeout(t.auth_db_budget_s):
                async with state.sessionmaker() as session:
                    principal = await authenticate(session, raw)
    except ProblemError:
        count(request, "auth_failed")
        log_event("auth_failed", reason="unavailable", request_id=request_id_of(request),
                  route=route_template(request))
        raise
    except (TimeoutError, SaTimeoutError):
        count(request, "auth_failed")
        log_event("auth_failed", reason="unavailable", request_id=request_id_of(request),
                  route=route_template(request))
        raise ProblemError(503, ReasonCode.UNAVAILABLE, Detail.UNAVAILABLE,
                           headers={"Retry-After": "1"}) from None
    if principal is None:
        _unauthenticated(request, "unknown_or_revoked")
    return principal


def require_role(*allowed: Role) -> Callable[..., Awaitable[Principal]]:
    async def dependency(request: Request,
                         principal: Principal = Depends(current_principal)) -> Principal:  # noqa: B008
        if principal.role is None or principal.role not in allowed:
            count(request, "role_denied")
            log_event("role_denied", route=route_template(request),
                      role=principal.role.value if principal.role else "unknown",
                      request_id=request_id_of(request), api_key_id=principal.api_key_id)
            raise ProblemError(403, ReasonCode.FORBIDDEN_ROLE, Detail.FORBIDDEN_ROLE)
        return principal

    return dependency


ANY_ROLE = require_role(Role.ADMIN, Role.ASSESSOR, Role.VIEWER)
WRITE_ROLE = require_role(Role.ADMIN, Role.ASSESSOR)
ADMIN_ROLE = require_role(Role.ADMIN)


def cross_org_miss(request: Request) -> None:
    count(request, "cross_org_miss")
    log_event("cross_org_miss", route=route_template(request), request_id=request_id_of(request))
