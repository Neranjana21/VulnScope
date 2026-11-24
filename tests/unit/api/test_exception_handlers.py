"""PD-01 / PD-03 / PD-16: every error is problem+json from fixed tables; OuterGuard stops anything
reaching uvicorn; secrets never reach a body, header or log record."""
from __future__ import annotations

import asyncio
import json
import logging
import re

import pytest
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import (
    RequestValidationError,
    ResponseValidationError,
    WebSocketRequestValidationError,
)
from fastapi.testclient import TestClient
from pydantic import BaseModel
from sqlalchemy.exc import TimeoutError as SaTimeoutError
from starlette.exceptions import HTTPException as StarletteHTTPException

from vulnscope.api.middleware import OuterGuard
from vulnscope.api.problem import Detail, ProblemError, install
from vulnscope.errors import PolicyReasonCode, ReasonCode

CANARY = "CANARY-9f3a71"
KEYS = {"type", "title", "status", "detail", "instance", "code", "request_id"}
UUID7 = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")


class Shape(BaseModel):
    x: int


def make_app(**guard: float) -> FastAPI:
    app = FastAPI(debug=False, docs_url=None, redoc_url=None, openapi_url=None)
    app.router.redirect_slashes = False
    install(app)

    @app.get("/ok")
    async def ok() -> dict[str, bool]:
        return {"ok": True}

    @app.post("/post")
    async def post(request: Request) -> dict[str, bool]:
        await request.body()
        return {"ok": True}

    @app.get("/q")
    async def q(n: int) -> dict[str, int]:
        return {"n": n}

    @app.get("/teapot")
    async def teapot() -> None:
        raise HTTPException(418, CANARY)

    @app.get("/e500")
    async def e500() -> None:
        raise HTTPException(500, CANARY)

    @app.get("/boom")
    async def boom() -> None:
        raise RuntimeError(CANARY)

    @app.get("/sa-timeout")
    async def sa_timeout() -> None:
        raise SaTimeoutError(CANARY)

    @app.get("/timeout")
    async def timeout() -> None:
        raise TimeoutError(CANARY)

    @app.get("/slow")
    async def slow() -> None:
        await asyncio.sleep(5)

    @app.get("/unavail")
    async def unavail() -> None:
        raise ProblemError(503, ReasonCode.UNAVAILABLE, Detail.UNAVAILABLE,
                           headers={"Retry-After": "1"})

    @app.get("/revoked")
    async def revoked() -> None:
        raise ProblemError(409, PolicyReasonCode.REVOKED, Detail.REVOKED, ledger_seq=7)

    @app.get("/badshape", response_model=Shape)
    async def badshape() -> dict[str, str]:
        return {"x": CANARY}

    app.add_middleware(OuterGuard, **guard)
    return app


@pytest.fixture
def client() -> TestClient:
    return TestClient(make_app(), raise_server_exceptions=True)


def check_problem(r, status: int, code: str) -> dict:
    assert r.status_code == status
    assert r.headers["content-type"].startswith("application/problem+json")
    body = r.json()
    assert set(body) - {"ledger_seq"} == KEYS
    assert body["code"] == code and body["status"] == status
    assert CANARY not in r.text
    for k in ("detail", "input", "ctx", "loc"):
        assert not isinstance(body.get(k), list)
    assert "input" not in body and "ctx" not in body and "loc" not in body
    return body


def test_ok_route_and_headers_on_success(client: TestClient) -> None:
    r = client.get("/ok", headers={"X-Request-ID": "attacker\nvalue"})
    assert r.status_code == 200
    assert UUID7.fullmatch(r.headers["x-request-id"])
    assert r.headers["cache-control"] == "no-store"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["content-security-policy"] == "default-src 'none'; frame-ancestors 'none'"
    assert r.headers["referrer-policy"] == "no-referrer"


def test_unknown_path_is_not_found_with_unmatched_instance(client: TestClient) -> None:
    r = client.get("/nope")
    body = check_problem(r, 404, "NOT_FOUND")
    assert body["instance"] == "unmatched"
    assert body["request_id"] == r.headers["x-request-id"]


def test_trailing_slash_is_404_not_redirect(client: TestClient) -> None:
    r = client.get("/ok/", follow_redirects=False)
    check_problem(r, 404, "NOT_FOUND")


def test_method_not_allowed_keeps_allow_header(client: TestClient) -> None:
    r = client.delete("/ok")
    check_problem(r, 405, "INVALID_REQUEST")
    assert "GET" in r.headers["allow"]


def test_options_carries_no_cors_headers(client: TestClient) -> None:
    r = client.options("/ok", headers={"Origin": "http://evil.example",
                                       "Access-Control-Request-Method": "GET"})
    assert not [h for h in r.headers if h.lower().startswith("access-control-")]


def test_query_validation_is_generic_422(client: TestClient) -> None:
    r = client.get("/q", params={"n": CANARY})
    check_problem(r, 422, "INVALID_REQUEST")


def test_http_exception_detail_is_never_copied(client: TestClient) -> None:
    check_problem(client.get("/teapot"), 418, "INVALID_REQUEST")
    check_problem(client.get("/e500"), 500, "INTERNAL_ERROR")


def test_response_validation_error_is_a_fixed_500() -> None:
    c = TestClient(make_app(), raise_server_exceptions=True)
    check_problem(c.get("/badshape"), 500, "INTERNAL_ERROR")


def test_problem_error_renders_policy_code_and_ledger_seq(client: TestClient) -> None:
    r = client.get("/revoked")
    body = check_problem(r, 409, "REVOKED")
    assert body["ledger_seq"] == 7


def test_problem_error_503_with_retry_after(client: TestClient) -> None:
    r = client.get("/unavail")
    check_problem(r, 503, "UNAVAILABLE")
    assert r.headers["retry-after"] == "1"


def test_problem_error_rejects_free_text_detail() -> None:
    with pytest.raises(TypeError):
        ProblemError(400, ReasonCode.INVALID_REQUEST, "free text")  # type: ignore[arg-type]


def test_every_detail_key_renders() -> None:
    from vulnscope.api.problem import DETAIL_TABLE

    assert set(DETAIL_TABLE) == set(Detail)
    for title, detail in DETAIL_TABLE.values():
        assert title and detail and CANARY not in title + detail


def test_exception_handler_keys_are_pinned() -> None:
    app = make_app()
    keys = set(app.exception_handlers)
    five = {ProblemError, StarletteHTTPException, RequestValidationError,
            ResponseValidationError, Exception}
    assert five <= keys
    assert keys - five <= {WebSocketRequestValidationError}


@pytest.mark.parametrize("path,status,code", [
    ("/boom", 500, "INTERNAL_ERROR"),
    ("/sa-timeout", 503, "UNAVAILABLE"),
    ("/timeout", 503, "UNAVAILABLE"),
])
def test_outer_guard_classifies_by_class_and_hides_text(path: str, status: int, code: str,
                                                        caplog: pytest.LogCaptureFixture) -> None:
    c = TestClient(make_app(), raise_server_exceptions=True)
    with caplog.at_level(logging.DEBUG):
        r = c.get(path)
    check_problem(r, status, code)
    leaked = any(CANARY in r_.getMessage() or r_.exc_info or r_.exc_text
                 for r_ in caplog.records if r_.name.startswith("vulnscope"))
    leaked = leaked or any(CANARY in str(r_.__dict__) for r_ in caplog.records)
    if leaked:
        pytest.fail("leak")
    events = [json.loads(r_.getMessage()) for r_ in caplog.records
              if r_.name == "vulnscope.api" and r_.getMessage().startswith("{")]
    assert any(e.get("event") == "unhandled_exception" and e.get("exc_class")
               and e.get("request_id") for e in events)


def test_outer_guard_request_deadline() -> None:
    c = TestClient(make_app(deadline_s=0.2), raise_server_exceptions=True)
    check_problem(c.get("/slow"), 503, "UNAVAILABLE")


def test_declared_oversize_body_is_413_before_any_read() -> None:
    c = TestClient(make_app(), raise_server_exceptions=True)
    r = c.post("/post", content=b"x" * 300_000)
    check_problem(r, 413, "INVALID_REQUEST")
    r2 = c.post("/post", content=b"x" * 1000)
    assert r2.status_code == 200


def test_instance_is_sanitised() -> None:
    c = TestClient(make_app(), raise_server_exceptions=True)
    r = c.get("/v1/x%0Ay" + "a" * 5000)
    body = check_problem(r, 404, "NOT_FOUND")
    assert body["instance"] == "unmatched"
    r2 = c.get("/ok/%0d%0a" + "b" * 5000)
    assert r2.json()["instance"] == "unmatched" and len(r2.json()["instance"]) < 64


def test_matched_route_instance_is_the_template() -> None:
    c = TestClient(make_app(), raise_server_exceptions=True)
    assert c.get("/unavail").json()["instance"] == "/unavail"


def test_inbound_request_id_is_ignored() -> None:
    c = TestClient(make_app(), raise_server_exceptions=True)
    r = c.get("/nope", headers={"X-Request-ID": "11111111-1111-1111-1111-111111111111"})
    assert r.headers["x-request-id"] != "11111111-1111-1111-1111-111111111111"
    assert r.json()["request_id"] == r.headers["x-request-id"]
