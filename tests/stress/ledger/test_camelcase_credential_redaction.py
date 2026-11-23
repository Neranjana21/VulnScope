# ruff: noqa: E501
"""Stress (R1): camelCase and similar credential keys (PB-12, owner rule).

Rule under test: split camelCase boundaries first, then compare the NORMALISED key (casefold,
strip, '-' -> '_') EXACTLY against the blocklist. No substring matching. A matching key (or
header-pair name, or HAR ``{"name": ..., "value": ...}`` name) has its STRING value replaced by
"[redacted]". Three shapes: dict key, header pair ``[name, value]`` and HAR name/value dict.
Memory backend here; the Postgres variant needs ``-p vulnscope_db_plugin`` and is not run by the
author. The canary must be absent from storage in every shape.
"""
from __future__ import annotations

import json
import uuid

import pytest
from ledger_r1_support import BASE_TS, mods, run

CANARY = "CANARY-CC-" + uuid.uuid4().hex
CHAIN = "intake:ffffffff-ffff-4fff-8fff-ffffffffffff"

MUST_REDACT = [
    "accessToken", "refreshToken", "idToken", "apiKey", "clientSecret", "secretKey", "sessionId",
    "authToken", "privateKey", "xApiKey", "csrfToken",
    "access_token", "refresh_token", "id_token", "api_key", "client_secret", "secret_key",
    "session_id", "auth_token", "private_key", "x_api_key", "csrf_token",
    "access-token", "refresh-token", "id-token", "api-key", "client-secret", "secret-key",
    "session-id", "auth-token", "private-key", "x-api-key", "csrf-token",
    "Access-Token", "ACCESS_TOKEN", "AccessToken", "APIKey", "X-Api-Key", "Client-Secret",
    "  accessToken  ", " token ", "\tx-api-key\n", " Authorization ",
]

MUST_PRESERVE = [
    "tokenizer_name", "token_count", "secret_ref", "authorization_basis", "sessions_total",
    "monkey", "passenger", "keyboard", "bearer_count",
    # harmless words containing key / token / pass / session inside longer words
    "turkey", "donkey", "hockey", "jockey", "keystone", "keyframe", "keynote", "hotkeys_enabled",
    "tokenize", "tokenizer", "tokenCount", "tokenBucketSize", "tokenizerName",
    "passage", "compass", "bypass", "passthrough", "passive", "passport_country", "classpath",
    "sessionization", "sessionsTotal", "session_count", "sessionLengthSeconds",
    "secretRef", "secretary", "secretion", "authorizationBasis", "authorization_basis_id",
    "passwordPolicy", "password_policy", "bearerCount", "apiKeyId", "api_key_id", "keyId",
    "primary_key_name", "monkeyBusiness", "Content-Type", "X-Ok", "accept", "user_agent",
]


def _blob(entries) -> str:
    return json.dumps([dict(e.payload) for e in entries], ensure_ascii=True, sort_keys=True)


async def _store(payload):
    b = mods().memory_backend.InMemoryChainBackend()
    e = await b.append(CHAIN, "policy.decision", "system", payload, BASE_TS)
    return e, [x async for x in b.read(CHAIN)]


def _secret(name: str) -> str:
    return ("Bearer " if "auth" in name.lower() and "token" not in name.lower() else "") + CANARY


def _norm_in(payload_keys):  # the stored dict key may be stripped by the sanitizer; find by strip
    return {k.strip(): v for k, v in payload_keys.items()}


# ------------------------------------------------------------------ dict-key shape
@pytest.mark.parametrize("key", MUST_REDACT)
async def test_dict_key_credential_is_redacted(key: str) -> None:
    e, rows = await _store({key: _secret(key), "outer": {"n": [{key: _secret(key)}]}})
    assert CANARY not in _blob(rows), f"canary stored under key {key!r}"
    assert "[redacted]" in json.dumps(dict(e.payload))
    top = [v for k, v in e.payload.items() if k.strip() == key.strip()]
    assert top == ["[redacted]"], f"{key!r} not redacted at top level"


@pytest.mark.parametrize("key", MUST_PRESERVE)
async def test_dict_key_harmless_is_preserved(key: str) -> None:
    e, _ = await _store({key: "plain-value", "n": {key: "plain-value"}})
    assert e.payload[key] == "plain-value" and e.payload["n"][key] == "plain-value"  # type: ignore[index]
    assert "[redacted]" not in json.dumps(dict(e.payload))


# ------------------------------------------------------------------ header-pair shape
@pytest.mark.parametrize("key", MUST_REDACT)
async def test_header_pair_credential_is_redacted(key: str) -> None:
    for pair in ([key, _secret(key)], (key, _secret(key))):
        e, rows = await _store({"headers": [pair, ["X-Ok", "fine"]]})
        got = [list(p) for p in e.payload["headers"]]  # type: ignore[union-attr]
        assert got[0][1] == "[redacted]" and got[0][0].strip() == key.strip()
        assert got[1] == ["X-Ok", "fine"]
        assert CANARY not in _blob(rows)


@pytest.mark.parametrize("key", MUST_PRESERVE)
async def test_header_pair_harmless_is_preserved(key: str) -> None:
    e, _ = await _store({"headers": [[key, "plain-value"], (key, "plain-value")]})
    assert [list(p) for p in e.payload["headers"]] == [[key, "plain-value"]] * 2  # type: ignore[union-attr]


# ------------------------------------------------------------------ HAR name/value shape
@pytest.mark.parametrize("key", MUST_REDACT)
async def test_har_name_value_credential_is_redacted(key: str) -> None:
    har = {"log": {"entries": [{"request": {
        "headers": [{"name": key, "value": _secret(key)}, {"name": "X-Ok", "value": "fine"}],
        "cookies": [{"name": key, "value": _secret(key), "path": "/"}],
        "queryString": [{"name": key, "value": _secret(key)}],
    }}]}}
    e, rows = await _store(har)
    req = e.payload["log"]["entries"][0]["request"]  # type: ignore[index]
    assert req["headers"][0]["value"] == "[redacted]" and req["headers"][0]["name"].strip() == key.strip()
    assert req["headers"][1] == {"name": "X-Ok", "value": "fine"}
    assert req["cookies"][0]["value"] == "[redacted]" and req["cookies"][0]["path"] == "/"
    assert req["queryString"][0]["value"] == "[redacted]"
    assert CANARY not in _blob(rows)


@pytest.mark.parametrize("key", MUST_PRESERVE)
async def test_har_name_value_harmless_is_preserved(key: str) -> None:
    har = {"headers": [{"name": key, "value": "plain-value"}]}
    e, _ = await _store(har)
    assert e.payload["headers"] == [{"name": key, "value": "plain-value"}]
    assert "sanitized" not in e.payload


# ------------------------------------------------------------------ properties of the rule
async def test_non_string_values_and_containers_under_credential_keys_do_not_leak() -> None:
    e, rows = await _store({"accessToken": {"nested": CANARY}, "apiKey": [CANARY, CANARY], "idToken": 12345})
    assert CANARY not in _blob(rows)


async def test_redaction_is_idempotent_and_agrees_across_shapes() -> None:
    c = mods().canonical
    for key in ("accessToken", "x-api-key", "ACCESS_TOKEN"):
        as_dict = c.sanitize_payload({key: CANARY})
        as_pair = c.sanitize_payload({"h": [[key, CANARY]]})
        as_har = c.sanitize_payload({"h": [{"name": key, "value": CANARY}]})
        assert as_dict[key] == "[redacted]"
        assert list(as_pair["h"][0]) == [key, "[redacted]"]  # type: ignore[index]
        assert as_har["h"][0]["value"] == "[redacted]"  # type: ignore[index]
        for out in (as_dict, as_pair, as_har):
            assert c.sanitize_payload(out) == out and CANARY not in json.dumps(out)


async def test_split_happens_before_matching_not_substring() -> None:
    """'monkey' ends in 'key' and 'passenger' starts with 'pass': exact match only."""
    e, _ = await _store({"monkey": "m", "passenger": "p", "keyboard": "k", "xapikey": CANARY})
    assert (e.payload["monkey"], e.payload["passenger"], e.payload["keyboard"]) == ("m", "p", "k")


@pytest.mark.integration
def test_postgres_camelcase_credentials_redacted_and_harmless_preserved(request: pytest.FixtureRequest) -> None:
    from ledger_r1_support import pg_admin_fetch, pg_backend, pg_scratch

    db = pg_scratch(request)
    cid = f"intake:{uuid.uuid4()}"
    payloads = [
        {k: CANARY for k in MUST_REDACT},
        {"h": [[k, CANARY] for k in MUST_REDACT]},
        {"h": [{"name": k, "value": CANARY} for k in MUST_REDACT]},
        {k: "plain-value" for k in MUST_PRESERVE},
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
    assert all(rows[3].payload[k] == "plain-value" for k in MUST_PRESERVE)
