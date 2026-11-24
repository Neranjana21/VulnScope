"""PD-04: hostile JSON never reaches a 5xx; statuses are pinned per row (bodies.read_json)."""
from __future__ import annotations

import json
from typing import Any

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from vulnscope.api.bodies import read_json
from vulnscope.api.middleware import OuterGuard
from vulnscope.api.problem import install

JSON_HDR = {"content-type": "application/json"}


def make_client(cap: int = 300_000) -> TestClient:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    install(app)

    @app.post("/j")
    async def j(request: Request) -> dict[str, Any]:
        tree = await read_json(request, cap)
        return {"ok": True, "type": type(tree).__name__}

    @app.post("/small")
    async def small(request: Request) -> dict[str, bool]:
        await read_json(request, 1024)
        return {"ok": True}

    app.add_middleware(OuterGuard)
    return TestClient(app, raise_server_exceptions=True)


@pytest.fixture(scope="module")
def client() -> TestClient:
    return make_client()


def nested(depth: int) -> bytes:
    return b'{"a":' * depth + b"1" + b"}" * depth


ROWS: list[tuple[str, bytes, int]] = [
    ("empty", b"", 400),
    ("truncated", b'{"a":', 400),
    ("not json", b"hello", 400),
    ("100k deep brackets", b"[" * 100_000, 400),
    ("deep but small objects past bracket cap", b"[" * 1025 + b"]" * 1025, 400),
    ("5000 digit int", b'{"a":' + b"9" * 5000 + b"}", 400),
    ("NaN", b'{"a":NaN}', 400),
    ("Infinity", b'{"a":Infinity}', 400),
    ("-Infinity", b'{"a":-Infinity}', 400),
    ("1e999", b'{"a":1e999}', 400),
    ("duplicate keys", b'{"a":1,"a":2}', 400),
    ("invalid utf8", b"\xff\xfe\x00", 400),
    ("utf8 bom", b"\xef\xbb\xbf{}", 400),
    ("600 keys", json.dumps({f"k{i}": 1 for i in range(600)}).encode(), 400),
    ("lone surrogate", b'{"a":"\\ud800"}', 422),
    ("NUL", b'{"a":"\\u0000"}', 422),
    ("bidi override", b'{"a":"\\u202e"}', 422),
    ("newline outside statement", b'{"a":"x\\ny"}', 422),
    ("C1 control", b'{"a":"\\u0085"}', 422),
    ("depth 13", nested(13), 422),
    ("20001 nodes", json.dumps(list(range(20_001))).encode(), 422),
    ("8193 char string", json.dumps({"a": "x" * 8193}).encode(), 422),
    ("8193 char key", json.dumps({"x" * 8193: 1}).encode(), 422),
    ("depth 12 ok", nested(12), 200),
    ("plain ok", b'{"a":[1,2,{"b":"c"}]}', 200),
    ("statement newline allowed", b'{"authorization":{"statement":"a\\nb"}}', 200),
    ("8192 char string ok", json.dumps({"a": "x" * 8192}).encode(), 200),
    ("17 digit int ok", b'{"a":12345678901234567}', 200),
]


@pytest.mark.parametrize("label,body,status", ROWS, ids=[r[0] for r in ROWS])
def test_row(client: TestClient, label: str, body: bytes, status: int) -> None:
    r = client.post("/j", content=body, headers=JSON_HDR)
    assert r.status_code == status, label
    if status != 200:
        assert r.headers["content-type"].startswith("application/problem+json")
        assert r.json()["code"] == "INVALID_REQUEST"
    assert client.get("/healthz-does-not-exist").status_code == 404  # process still responsive


def test_wrong_content_type_is_415(client: TestClient) -> None:
    for ct in ("text/plain", "application/xml", "application/jsonx"):
        r = client.post("/j", content=b"{}", headers={"content-type": ct})
        assert r.status_code == 415 and r.json()["code"] == "INVALID_REQUEST"
    assert client.post("/j", content=b"{}", headers={"content-type": "application/json"}
                       ).status_code == 200
    mixed = {"content-type": "Application/JSON; charset=utf-8"}
    assert client.post("/j", content=b"{}", headers=mixed).status_code == 200
    assert client.post("/j", content=b"{}").status_code == 415


def test_per_route_cap_is_413() -> None:
    c = make_client()
    r = c.post("/small", content=b'{"a":"' + b"x" * 2000 + b'"}', headers=JSON_HDR)
    assert r.status_code == 413 and r.json()["code"] == "INVALID_REQUEST"


def test_chunked_body_over_cap_is_cut_at_read_time() -> None:
    c = make_client()

    def gen():
        for _ in range(10):
            yield b'{"a":"' + b"x" * 500 if _ == 0 else b"y" * 500

    r = c.post("/small", content=gen(), headers=JSON_HDR)
    assert r.status_code == 413
