# ruff: noqa: E501
"""Stress (R1): header-pair redaction (owner decision 2026-11-23, extends B-R1-3).

HTTP headers often arrive as ``[name, value]`` pairs or lists of pairs, not as dict keys. A pair
whose NAME exactly (case-insensitively) matches the blocklist (authorization, proxy-authorization,
cookie, set-cookie, x-api-key, password, passwd, secret, token, api_key, apikey, private_key,
credential, client_secret) must have its STRING value replaced by the fixed string "[redacted]",
whatever the nesting (lists, tuples, dicts) and whichever container type the pair uses. Pairs with
other names are preserved verbatim. The canary is absent from storage (memory and Postgres).
Tuples are stored as lists (normalisation), so stored pairs are compared as lists.
"""
from __future__ import annotations

import json
import uuid

import pytest
from ledger_r1_support import BASE_TS, mods, run

CANARY = "CANARY-HDR-" + uuid.uuid4().hex
CHAIN = "intake:eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
BLOCKLIST = ["authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "password",
             "passwd", "secret", "token", "api_key", "apikey", "private_key", "credential", "client_secret"]


def _case_variants(name: str) -> list[str]:
    alt = "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(name))
    return sorted({name, name.upper(), name.title(), alt})


def _secret(name: str) -> str:
    return ("Bearer " if name.lower().endswith("authorization") else "") + CANARY


def _blob(entries) -> str:
    return json.dumps([dict(e.payload) for e in entries], ensure_ascii=True, sort_keys=True)


async def _store(payload):
    b = mods().memory_backend.InMemoryChainBackend()
    e = await b.append(CHAIN, "policy.decision", "system", payload, BASE_TS)
    return e, [x async for x in b.read(CHAIN)]


@pytest.mark.parametrize("name", BLOCKLIST)
async def test_single_pair_list_and_tuple_any_case(name: str) -> None:
    for n in _case_variants(name):
        for pair in ([n, _secret(name)], (n, _secret(name))):
            e, rows = await _store({"header": pair, "keep": ["X-Ok", "fine"]})
            assert list(e.payload["header"]) == [n, "[redacted]"], n
            assert list(e.payload["keep"]) == ["X-Ok", "fine"]
            assert CANARY not in _blob(rows)


@pytest.mark.parametrize("name", BLOCKLIST)
async def test_list_of_pairs_mixed_with_clean_pairs(name: str) -> None:
    headers = [[name.upper(), _secret(name)], ["X-Ok", "fine"], (name.title(), _secret(name)), ("Accept", "text/html")]
    e, rows = await _store({"request": {"headers": headers}})
    got = [list(p) for p in e.payload["request"]["headers"]]  # type: ignore[index]
    assert got == [[name.upper(), "[redacted]"], ["X-Ok", "fine"], [name.title(), "[redacted]"], ["Accept", "text/html"]]
    assert CANARY not in _blob(rows)


async def test_the_exact_example_from_the_owner() -> None:
    e, rows = await _store({"h": [["Authorization", "Bearer " + CANARY], ["X-Ok", "fine"]]})
    assert [list(p) for p in e.payload["h"]] == [["Authorization", "[redacted]"], ["X-Ok", "fine"]]  # type: ignore[union-attr]
    assert CANARY not in _blob(rows) and "Bearer" not in _blob(rows)


async def test_deeply_nested_pairs_in_lists_dicts_and_tuples() -> None:
    pair = ["Authorization", "Bearer " + CANARY]
    payload = {
        "a": [[pair]],
        "b": {"x": [{"headers": [pair, ("Set-Cookie", CANARY)]}]},
        "c": ((("Cookie", CANARY),),),
        "d": [{"y": {"z": [("X-Api-Key", CANARY), ["X-Ok", "fine"]]}}],
        "e": [[["Proxy-Authorization", "Basic " + CANARY]]],
    }
    e, rows = await _store(payload)
    text = json.dumps(dict(e.payload), sort_keys=True)
    assert CANARY not in text and CANARY not in _blob(rows) and text.count("[redacted]") == 6
    assert ["X-Ok", "fine"] in json.loads(text)["d"][0]["y"]["z"]


@pytest.mark.parametrize("pair", [["secret_ref", "vault://lab/s/1"], ["token_count", "17"], ["authorization_basis", "approved by alice"],
                                  ["X-Ok", "fine"], ["Accept", "text/html"], ["passwords_policy", "kept"], ["x-api-key-id", "kid-7"]])
async def test_non_blocklisted_pairs_are_preserved(pair) -> None:
    for container in (list(pair), tuple(pair)):
        e, _ = await _store({"headers": [container, ["Content-Type", "text/plain"]]})
        assert [list(p) for p in e.payload["headers"]] == [list(pair), ["Content-Type", "text/plain"]]  # type: ignore[union-attr]
        if isinstance(container, list):  # tuple -> list normalisation is not asserted either way
            assert "sanitized" not in e.payload


async def test_a_pair_is_redacted_even_when_its_value_looks_harmless() -> None:
    e, _ = await _store({"h": [["Authorization", "x"], ["Cookie", ""], ["Token", "0"]]})
    assert [list(p) for p in e.payload["h"]] == [["Authorization", "[redacted]"], ["Cookie", "[redacted]"], ["Token", "[redacted]"]]  # type: ignore[union-attr]


async def test_pair_redaction_is_idempotent_and_flags_the_alteration() -> None:
    c = mods().canonical
    payload = {"h": [["Authorization", "Bearer " + CANARY], ("Cookie", CANARY)]}
    once = c.sanitize_payload(payload)
    assert c.sanitize_payload(once) == once
    assert once.get("sanitized") is True and CANARY not in json.dumps(once)
    assert len(c.canonical_json(c.normalize_payload(once))) <= 65_536


async def test_pair_and_dict_key_redaction_agree() -> None:
    c = mods().canonical
    as_dict = c.sanitize_payload({"headers": {"Authorization": "Bearer " + CANARY}})
    as_pairs = c.sanitize_payload({"headers": [["Authorization", "Bearer " + CANARY]]})
    assert as_dict["headers"] == {"Authorization": "[redacted]"}  # type: ignore[comparison-overlap]
    assert [list(p) for p in as_pairs["headers"]] == [["Authorization", "[redacted]"]]  # type: ignore[union-attr]


@pytest.mark.integration
def test_postgres_pairs_redacted_and_canary_absent_from_storage(request: pytest.FixtureRequest) -> None:
    from ledger_r1_support import pg_admin_fetch, pg_backend, pg_scratch

    db = pg_scratch(request)
    cid = f"intake:{uuid.uuid4()}"
    payloads = [
        {"h": [["Authorization", "Bearer " + CANARY], ["X-Ok", "fine"]]},
        {"h": [("Cookie", CANARY), ("Set-Cookie", CANARY)], "n": {"x": [["X-Api-Key", CANARY]]}},
        {"deep": [[[["Proxy-Authorization", "Basic " + CANARY]]]]},
        {"h": [["secret_ref", "vault://lab/s/1"], ["token_count", "17"]]},
    ]

    async def go():
        engine, backend = await pg_backend(db)
        try:
            for p in payloads:
                await backend.append(cid, "policy.decision", "system", p, BASE_TS)
            return await mods().verify.verify(cid, backend), [e async for e in backend.read(cid)]
        finally:
            await engine.dispose()

    res, rows = run(go())
    assert (res.result, res.records) == ("ok", 4)
    stored = pg_admin_fetch(db, "SELECT payload::text AS p FROM ledger_entries WHERE chain_id = $1 ORDER BY seq", cid)
    assert len(stored) == 4 and not any(CANARY in r["p"] for r in stored)
    assert [list(p) for p in rows[0].payload["h"]] == [["Authorization", "[redacted]"], ["X-Ok", "fine"]]  # type: ignore[union-attr]
    assert [list(p) for p in rows[3].payload["h"]] == [["secret_ref", "vault://lab/s/1"], ["token_count", "17"]]  # type: ignore[union-attr]
