"""PB-12: camelCase is split before the exact normalised match (never a substring)."""
from __future__ import annotations

import pytest

from vulnscope.ledger import canonical as c


@pytest.mark.parametrize(
    "key,expected",
    [("accessToken", "access_token"), ("APIKey", "api_key"), ("xApiKey", "x_api_key"),
     ("Access-Token", "access_token"), (" sessionId ", "session_id"),
     ("ACCESS_TOKEN", "access_token"),
     ("tokenCount", "token_count"), ("apiKeyId", "api_key_id")],
)
def test_norm_key(key: str, expected: str) -> None:
    assert c._norm_key(key) == expected


@pytest.mark.parametrize("key", ["accessToken", "refreshToken", "idToken", "apiKey", "clientSecret",
                                 "secretKey", "sessionId", "authToken", "csrfToken", "privateKey"])
def test_camel_credentials_redacted_any_shape(key: str) -> None:
    out = c.sanitize_payload({key: "S", "h": [[key, "S"]], "r": [{"name": key, "value": "S"}]})
    assert out[key] == "[redacted]" and out["h"] == [[key, "[redacted]"]]
    assert out["r"] == [{"name": key, "value": "[redacted]"}]
    assert c.sanitize_payload(out) == out


@pytest.mark.parametrize("key", ["tokenizer_name", "token_count", "secret_ref", "sessions_total",
                                 "monkey", "passenger", "tokenBucketSize", "apiKeyId", "keyId"])
def test_harmless_keys_preserved(key: str) -> None:
    assert c.sanitize_payload({key: "v"}) == {key: "v"}
