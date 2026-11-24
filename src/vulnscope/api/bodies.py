"""Hostile-JSON-safe body reading (PD-04, rule 9). Runs only AFTER authentication.

Phase P (400): bytes, UTF-8, JSON syntax and bounds. Phase T (422): tree hygiene. Neither phase
touches the ledger. Nothing from the body is ever put into an error message.
"""
from __future__ import annotations

import json
from typing import Any, NoReturn

from starlette.requests import Request

from vulnscope.api.limits import (
    MAX_BRACKETS,
    MAX_DEPTH,
    MAX_FLOAT_LITERAL,
    MAX_INT_LITERAL,
    MAX_NODES,
    MAX_OBJECT_KEYS,
    MAX_STRING_CHARS,
)
from vulnscope.api.problem import Detail, ProblemError
from vulnscope.errors import ReasonCode

_BAD_CODEPOINTS = frozenset(
    [*range(0x200B, 0x2010), *range(0x202A, 0x202F), *range(0x2060, 0x2065),
     *range(0x2066, 0x206A), 0xFEFF, 0x2028, 0x2029])
_STATEMENT_PATH = ("authorization", "statement")


class _Reject(Exception):
    pass


def _bad_body() -> NoReturn:
    raise ProblemError(400, ReasonCode.INVALID_REQUEST, Detail.BAD_BODY)


def _bad_tree() -> NoReturn:
    raise ProblemError(422, ReasonCode.INVALID_REQUEST, Detail.BAD_REQUEST)


def _reject_constant(_: str) -> Any:
    raise _Reject


def _bounded_int(s: str) -> int:
    if len(s) > MAX_INT_LITERAL:
        raise _Reject
    return int(s)


def _bounded_float(s: str) -> float:
    if len(s) > MAX_FLOAT_LITERAL:
        raise _Reject
    v = float(s)
    if v != v or v in (float("inf"), float("-inf")):
        raise _Reject
    return v


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    if len(pairs) > MAX_OBJECT_KEYS:
        raise _Reject
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise _Reject
        out[k] = v
    return out


def parse_json_bytes(raw: bytes) -> Any:
    """Phase P. Raises ``ProblemError(400)``; never any other exception type."""
    if not raw:
        _bad_body()
    try:
        text = raw.decode("utf-8", errors="strict")
        if raw.count(b"[") + raw.count(b"{") > MAX_BRACKETS:
            _bad_body()
        return json.loads(
            text, parse_constant=_reject_constant, parse_int=_bounded_int,
            parse_float=_bounded_float, object_pairs_hook=_strict_object)
    except ProblemError:
        raise
    except (_Reject, RecursionError, ValueError, UnicodeError, OverflowError):
        _bad_body()


def _check_string(s: str, *, allow_newline: bool) -> None:
    if len(s) > MAX_STRING_CHARS:
        _bad_tree()
    for ch in s:
        cp = ord(ch)
        if 0xD800 <= cp <= 0xDFFF or cp == 0 or cp in _BAD_CODEPOINTS:
            _bad_tree()
        if cp < 0x20 or 0x7F <= cp <= 0x9F:
            if allow_newline and ch in "\n\t":
                continue
            _bad_tree()


def check_tree(tree: Any) -> None:
    """Phase T, iterative (no recursion): depth, node count, string hygiene."""
    stack: list[tuple[Any, int, tuple[str, ...]]] = [(tree, 1, ())]
    nodes = 0
    while stack:
        node, depth, path = stack.pop()
        nodes += 1
        if nodes > MAX_NODES:
            _bad_tree()
        if isinstance(node, dict):
            if depth > MAX_DEPTH:
                _bad_tree()
            for k, v in node.items():
                _check_string(k, allow_newline=False)
                stack.append((v, depth + 1, (*path, k)))
        elif isinstance(node, list):
            if depth > MAX_DEPTH:
                _bad_tree()
            for v in node:
                stack.append((v, depth + 1, (*path, "*")))
        elif isinstance(node, str):
            _check_string(node, allow_newline=path == _STATEMENT_PATH)


async def read_raw(request: Request, max_bytes: int) -> bytes:
    media = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if media != "application/json":
        raise ProblemError(415, ReasonCode.INVALID_REQUEST, Detail.UNSUPPORTED_MEDIA_TYPE)
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > max_bytes:
            raise ProblemError(413, ReasonCode.INVALID_REQUEST, Detail.PAYLOAD_TOO_LARGE)
        chunks.append(chunk)
    return b"".join(chunks)


async def read_json(request: Request, max_bytes: int) -> Any:
    """Read, parse (phase P) and check (phase T) the JSON body. Call only after authentication."""
    raw = await read_raw(request, max_bytes)
    tree = parse_json_bytes(raw)
    check_tree(tree)
    return tree
