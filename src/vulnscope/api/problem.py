"""problem+json rendering and the global exception handlers (PD-01, PD-16, ADR-0006).

``detail`` and ``title`` come only from the closed ``DETAIL_TABLE``; no request text, exception text
or path is ever copied into a body. ``instance`` is the matched route template, or ``unmatched``.
All handlers are installed here, on the app object, never per router.
"""
from __future__ import annotations

from collections.abc import Mapping
from enum import Enum
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError, ResponseValidationError
from fastapi.responses import JSONResponse, Response
from starlette.exceptions import HTTPException as StarletteHTTPException

from vulnscope.api.limits import MEDIA_TYPE_PROBLEM
from vulnscope.errors import PolicyReasonCode, ProblemDetail, ReasonCode

Code = ReasonCode | PolicyReasonCode


class Detail(str, Enum):
    UNAUTHENTICATED = "unauthenticated"
    FORBIDDEN_ROLE = "forbidden_role"
    NOT_FOUND = "not_found"
    BAD_BODY = "bad_body"
    BAD_REQUEST = "bad_request"
    METHOD_NOT_ALLOWED = "method_not_allowed"
    PAYLOAD_TOO_LARGE = "payload_too_large"
    UNSUPPORTED_MEDIA_TYPE = "unsupported_media_type"
    IDEMPOTENCY_CONFLICT = "idempotency_conflict"
    REVOKED = "revoked"
    EXPIRED = "expired"
    WINDOW_NOT_OPEN = "window_not_open"
    RATE_LIMITED = "rate_limited"
    TARGET_DENIED = "target_denied"
    TARGET_NOT_IN_SCOPE = "target_not_in_scope"
    AUTH_NOT_CONFIRMED = "auth_not_confirmed"
    SCOPE_EMPTY = "scope_empty"
    RATE_ABOVE_CEILING = "rate_above_ceiling"
    WINDOW_MISSING = "window_missing"
    WINDOW_EXPIRED = "window_expired"
    WINDOW_NAIVE_DATETIME = "window_naive_datetime"
    WINDOW_TOO_LONG = "window_too_long"
    SECRET_INLINE = "secret_inline"
    UNKNOWN_FIELD = "unknown_field"
    PROFILE_NOT_ENABLED = "profile_not_enabled"
    INTERNAL = "internal"
    UNAVAILABLE = "unavailable"


DETAIL_TABLE: dict[Detail, tuple[str, str]] = {
    Detail.UNAUTHENTICATED: ("Unauthenticated", "A valid API key is required."),
    Detail.FORBIDDEN_ROLE: ("Forbidden", "The API key's role does not allow this action."),
    Detail.NOT_FOUND: ("Not found", "The requested resource was not found."),
    Detail.BAD_BODY: ("Bad request", "The request body could not be parsed."),
    Detail.BAD_REQUEST: ("Invalid request", "The request is not valid."),
    Detail.METHOD_NOT_ALLOWED: ("Method not allowed", "The method is not allowed for this route."),
    Detail.PAYLOAD_TOO_LARGE: ("Payload too large", "The request body exceeds the size limit."),
    Detail.UNSUPPORTED_MEDIA_TYPE: ("Unsupported media type", "Use application/json."),
    Detail.IDEMPOTENCY_CONFLICT: (
        "Idempotency conflict", "The Idempotency-Key was used with a different request."),
    Detail.REVOKED: ("Engagement revoked", "The engagement has been revoked."),
    Detail.EXPIRED: ("Engagement window ended", "The engagement window has ended."),
    Detail.WINDOW_NOT_OPEN: ("Window not open", "The engagement window has not opened yet."),
    Detail.RATE_LIMITED: ("Rate limited", "The rate limit for this engagement was reached."),
    Detail.TARGET_DENIED: ("Target denied", "A target is denied by policy."),
    Detail.TARGET_NOT_IN_SCOPE: ("Target not in scope", "A target is not covered by the scope."),
    Detail.AUTH_NOT_CONFIRMED: ("Authorization not confirmed", "Authorization is not confirmed."),
    Detail.SCOPE_EMPTY: ("Scope empty", "The scope has no allowed targets."),
    Detail.RATE_ABOVE_CEILING: ("Rate above ceiling", "The rate limit exceeds the ceiling."),
    Detail.WINDOW_MISSING: ("Window missing", "The engagement window is missing."),
    Detail.WINDOW_EXPIRED: ("Window expired", "The engagement window has already ended."),
    Detail.WINDOW_NAIVE_DATETIME: (
        "Naive datetime", "Timestamps must be timezone-aware UTC."),
    Detail.WINDOW_TOO_LONG: ("Window too long", "The engagement window is too long."),
    Detail.SECRET_INLINE: ("Secret inline", "A secret appears to be inline; use a reference."),
    Detail.UNKNOWN_FIELD: ("Unknown field", "The request contains an unknown field."),
    Detail.PROFILE_NOT_ENABLED: ("Profile not enabled", "The profile is not enabled."),
    Detail.INTERNAL: ("Internal error", "An internal error occurred."),
    Detail.UNAVAILABLE: ("Service unavailable", "The service is temporarily unavailable."),
}


class ProblemError(Exception):
    """Raised by handlers; carries a code, a status and a closed-set ``Detail`` key only."""

    def __init__(
        self,
        status: int,
        code: Code,
        detail: Detail,
        *,
        ledger_seq: int | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        if not isinstance(detail, Detail):
            raise TypeError("detail must be a Detail member")
        if not isinstance(code, ReasonCode | PolicyReasonCode):
            raise TypeError("code must be a ReasonCode or PolicyReasonCode")
        super().__init__(detail.value)
        self.status = status
        self.code = code
        self.detail = detail
        self.ledger_seq = ledger_seq
        self.headers = dict(headers or {})


def route_template(request: Request) -> str:
    route = request.scope.get("route")
    path = getattr(route, "path", None)
    if isinstance(path, str) and len(path) < 64 and path.isprintable():
        return path
    return "unmatched"


def request_id_of(request: Request) -> str:
    state = request.scope.get("state") or {}
    rid = state.get("request_id") if isinstance(state, dict) else None
    return rid if isinstance(rid, str) else ""


def problem_body(
    *, status: int, code: Code, detail: Detail, instance: str, request_id: str | None,
    ledger_seq: int | None = None,
) -> dict[str, Any]:
    title, text = DETAIL_TABLE[detail]
    model = ProblemDetail(
        title=title, status=status, detail=text, instance=instance, code=code,
        ledger_seq=ledger_seq, request_id=request_id or None)
    return model.model_dump(mode="json", exclude_none=True)


def problem_response(
    *, status: int, code: Code, detail: Detail, instance: str, request_id: str | None,
    ledger_seq: int | None = None, headers: Mapping[str, str] | None = None,
) -> JSONResponse:
    return JSONResponse(
        problem_body(status=status, code=code, detail=detail, instance=instance,
                     request_id=request_id, ledger_seq=ledger_seq),
        status_code=status, media_type=MEDIA_TYPE_PROBLEM, headers=dict(headers or {}))


def _from_problem_error(request: Request, exc: ProblemError) -> Response:
    return problem_response(
        status=exc.status, code=exc.code, detail=exc.detail, instance=route_template(request),
        request_id=request_id_of(request), ledger_seq=exc.ledger_seq, headers=exc.headers)


async def _problem_error_handler(request: Request, exc: Exception) -> Response:
    assert isinstance(exc, ProblemError)
    return _from_problem_error(request, exc)


async def _http_exception_handler(request: Request, exc: Exception) -> Response:
    assert isinstance(exc, StarletteHTTPException)
    headers = {k: v for k, v in (exc.headers or {}).items() if k.lower() == "allow"}
    if exc.status_code == 404:
        status, code, detail = 404, ReasonCode.NOT_FOUND, Detail.NOT_FOUND
    elif exc.status_code == 405:
        status, code, detail = 405, ReasonCode.INVALID_REQUEST, Detail.METHOD_NOT_ALLOWED
    elif 400 <= exc.status_code < 500:
        status, code, detail = exc.status_code, ReasonCode.INVALID_REQUEST, Detail.BAD_REQUEST
    else:
        status, code, detail = 500, ReasonCode.INTERNAL_ERROR, Detail.INTERNAL
    return problem_response(status=status, code=code, detail=detail,
                            instance=route_template(request),
                            request_id=request_id_of(request), headers=headers)


async def _validation_handler(request: Request, exc: Exception) -> Response:
    return problem_response(
        status=422, code=ReasonCode.INVALID_REQUEST, detail=Detail.BAD_REQUEST,
        instance=route_template(request), request_id=request_id_of(request))


async def _internal_handler(request: Request, exc: Exception) -> Response:
    return problem_response(
        status=500, code=ReasonCode.INTERNAL_ERROR, detail=Detail.INTERNAL,
        instance=route_template(request), request_id=request_id_of(request))


def install(app: FastAPI) -> None:
    """Install every handler on the app object (the only place handlers are registered)."""
    app.add_exception_handler(ProblemError, _problem_error_handler)
    app.add_exception_handler(StarletteHTTPException, _http_exception_handler)
    app.add_exception_handler(RequestValidationError, _validation_handler)
    app.add_exception_handler(ResponseValidationError, _internal_handler)
    app.add_exception_handler(Exception, _internal_handler)
