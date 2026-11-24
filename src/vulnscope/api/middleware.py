"""``OuterGuard``: the outermost pure-ASGI middleware (PD-03, PD-09, PD-16).

It assigns a server-generated request id (an inbound ``X-Request-ID`` is ignored), adds the
security headers to every response, rejects a DECLARED oversize body before reading anything,
bounds the whole request with a deadline, and catches every ``Exception`` itself so nothing
propagates to Starlette's ServerErrorMiddleware (which would re-raise into uvicorn's logger with a
traceback). Classification is by exception CLASS only; exception text is never read or logged.
"""
from __future__ import annotations

import asyncio

from sqlalchemy.exc import InterfaceError, OperationalError
from sqlalchemy.exc import TimeoutError as SaTimeoutError
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from vulnscope.api.limits import MAX_BODY_BYTES, Timeouts
from vulnscope.api.logging import log_event
from vulnscope.api.problem import Detail, ProblemError, problem_response
from vulnscope.errors import ReasonCode
from vulnscope.models.schemas.common import uuid7

SECURITY_HEADERS = {
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
    "referrer-policy": "no-referrer",
}
_UNAVAILABLE = (SaTimeoutError, TimeoutError, ConnectionError, OSError, InterfaceError,
                OperationalError)


def _route_instance(scope: Scope) -> str:
    path = getattr(scope.get("route"), "path", None)
    if isinstance(path, str) and len(path) < 64 and path.isprintable():
        return path
    return "unmatched"


class OuterGuard:
    def __init__(self, app: ASGIApp, *, deadline_s: float | None = None,
                 max_declared_body: int = MAX_BODY_BYTES) -> None:
        self.app = app
        self.deadline_s = deadline_s
        self.max_declared_body = max_declared_body

    def _deadline(self, scope: Scope) -> float:
        if self.deadline_s is not None:
            return self.deadline_s
        state = getattr(getattr(scope.get("app"), "state", None), "d", None)
        timeouts = getattr(state, "timeouts", None)
        return timeouts.request_deadline_s if isinstance(timeouts, Timeouts) else 30.0

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        rid = uuid7()
        scope.setdefault("state", {})["request_id"] = rid
        started = False

        async def send_wrapped(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
                headers = [(k, v) for k, v in message.get("headers", [])
                           if k.lower() not in SECURITY_HEADERS and k.lower() != b"x-request-id"]
                headers += [(k.encode(), v.encode()) for k, v in SECURITY_HEADERS.items()]
                headers.append((b"x-request-id", rid.encode()))
                message = {**message, "headers": headers}
            await send(message)

        declared = _declared_length(scope)
        if declared is not None and declared > self.max_declared_body:
            resp = problem_response(
                status=413, code=ReasonCode.INVALID_REQUEST, detail=Detail.PAYLOAD_TOO_LARGE,
                instance="unmatched", request_id=rid)
            await resp(scope, receive, send_wrapped)
            return
        try:
            async with asyncio.timeout(self._deadline(scope)):
                await self.app(scope, receive, send_wrapped)
        except Exception as exc:  # noqa: BLE001 - never BaseException: cancellation passes
            self._log(exc, rid)
            if started:
                return
            if isinstance(exc, ProblemError):
                status, code, detail = exc.status, exc.code, exc.detail
            elif isinstance(exc, _UNAVAILABLE):
                status, code, detail = 503, ReasonCode.UNAVAILABLE, Detail.UNAVAILABLE
            else:
                status, code, detail = 500, ReasonCode.INTERNAL_ERROR, Detail.INTERNAL
            headers: dict[str, str] = {"Retry-After": "1"} if status == 503 else {}
            resp = problem_response(
                status=status, code=code, detail=detail, instance=_route_instance(scope),
                request_id=rid, headers=headers)
            await resp(scope, receive, send_wrapped)

    @staticmethod
    def _log(exc: BaseException, rid: str) -> None:
        cls = type(exc)
        log_event("unhandled_exception", exc_class=f"{cls.__module__}.{cls.__qualname__}",
                  request_id=rid)


def _declared_length(scope: Scope) -> int | None:
    for k, v in scope.get("headers", []):
        if k == b"content-length":
            try:
                return int(v)
            except ValueError:
                return None
    return None


