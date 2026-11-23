# ruff: noqa: E501
"""Post-gate fix round 1 (PB-1..PB-4, PB-8): normalised exact key matching, non-string leaves,
HAR and 3-item shapes, always re-sanitize, no __context__ on signer errors."""
from __future__ import annotations

import json
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest

from vulnscope.ledger import canonical as c
from vulnscope.ledger.errors import SignerKeyError
from vulnscope.ledger.memory_backend import InMemoryChainBackend
from vulnscope.ledger.signer import Ed25519FileSigner, Ed25519PublicVerifier

CANARY = "CANARY-PB-" + uuid.uuid4().hex
CHAIN = "intake:pbfix"
TS = datetime(2026, 11, 23, tzinfo=UTC)

PB1_NAMES = [
    "api-key", "access_token", "refresh_token", "id_token", "secret_key", "x-csrf-token", "session",
    "pwd", "authtoken", "authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key",
    "password", "passwd", "secret", "token", "api_key", "apikey", "private_key", "credential",
    "client_secret",
    # normalised variants a naive exact match misses
    "Authorization ", " Cookie", "authToken", "AuthToken", "x_api_key", "X_Api_Key", "client-secret",
    "private-key", "X-CSRF-Token", "x_csrf_token", "Access-Token", "SESSION", "x-auth-token",
    "sessionid", "passphrase", "bearer", "aws_secret_access_key", "\tpassword\n",
]
PRESERVED = ["secret_ref", "token_count", "authorization_basis", "authorizations", "passwords_policy",
             "x-api-key-id", "session_count", "tokens", "Set-Cookie2", "secretary", "cookies", "name"]


async def _store(payload: object) -> tuple[dict[str, object], str]:
    b = InMemoryChainBackend()
    e = await b.append(CHAIN, "policy.decision", "system", payload, TS)  # type: ignore[arg-type]
    (row,) = [x async for x in b.read(CHAIN)]
    return dict(e.payload), json.dumps(dict(row.payload), sort_keys=True)


# ------------------------------------------------------------------ PB-1
@pytest.mark.parametrize("name", PB1_NAMES)
async def test_pb1_every_name_and_normalised_variant_is_redacted(name: str) -> None:
    payload = {name: CANARY, "n": {"deep": [{name: CANARY}]}}
    stored, blob = await _store(payload)
    assert CANARY not in blob and "[redacted]" in blob


@pytest.mark.parametrize("name", PRESERVED)
async def test_pb1_matching_stays_exact_never_a_substring(name: str) -> None:
    stored, blob = await _store({name: "kept-value"})
    assert stored == {name: "kept-value"}


# ------------------------------------------------------------------ PB-2
@pytest.mark.parametrize("name", PB1_NAMES[:23])
@pytest.mark.parametrize("value", [918273645, True, False, 1.5, -7, 0])
async def test_pb2_non_string_leaves_under_a_blocked_key_are_redacted(name: str, value: object) -> None:
    stored, _ = await _store({name: value, "n": {name: value}, "l": [{name: value}]})
    assert stored[name] == "[redacted]"
    assert stored["n"] == {name: "[redacted]"} and stored["l"] == [{name: "[redacted]"}]


def test_pb2_pair_values_too_and_none_is_kept() -> None:
    out = c.sanitize_payload({"h": [["Authorization", 918273645], ("Cookie", 2.5), ["token", True]], "t": {"token": None}})
    assert out["h"] == [["Authorization", "[redacted]"], ["Cookie", "[redacted]"], ["token", "[redacted]"]]
    assert out["t"] == {"token": None}


def test_pb2_int_range_marker_does_not_win_over_redaction() -> None:
    assert c.sanitize_payload({"password": 2**80})["password"] == "[redacted]"


# ------------------------------------------------------------------ PB-3
async def test_pb3_har_name_value_objects_are_redacted() -> None:
    headers = [{"name": "Authorization", "value": "Bearer " + CANARY}, {"name": "Accept", "value": "text/html"},
               {"name": "set-cookie", "value": CANARY, "comment": "kept"}, {"key": "X-Api-Key", "value": 918273645},
               {"header": "Cookie", "value": CANARY}]
    stored, blob = await _store({"log": {"entries": [{"request": {"headers": headers}}]}})
    assert CANARY not in blob and "918273645" not in blob
    got = stored["log"]["entries"][0]["request"]["headers"]  # type: ignore[index]
    assert got[1] == {"name": "Accept", "value": "text/html"} and got[2]["comment"] == "kept"
    assert got[0]["name"] == "Authorization" and got[0]["value"] == "[redacted]"


async def test_pb3_top_level_har_object_and_unrelated_name_value_are_handled() -> None:
    stored, blob = await _store({"name": "Authorization", "value": CANARY})
    assert CANARY not in blob and stored["name"] == "Authorization"
    stored, _ = await _store({"name": "Accept", "value": "text/html"})
    assert stored == {"name": "Accept", "value": "text/html"}


async def test_pb3_three_item_sequences_redact_the_value_only() -> None:
    stored, blob = await _store({"h": [["Authorization", CANARY, "extra"], ("X-Ok", "v", "w"), ["Cookie", CANARY, 5]]})
    assert CANARY not in blob
    assert stored["h"] == [["Authorization", "[redacted]", "extra"], ["X-Ok", "v", "w"], ["Cookie", "[redacted]", 5]]


def test_pb3_free_text_credentials_are_out_of_scope_documented() -> None:
    doc = " ".join((c.sanitize_payload.__doc__ or "").split())
    assert "Free text" in doc and "NOT detected" in doc


# ------------------------------------------------------------------ PB-4
async def test_pb4_a_key_added_after_sanitizing_is_redacted_by_append() -> None:
    s = c.sanitize_payload({"a": 1})
    s["headers"] = {"Authorization": CANARY}  # type: ignore[assignment]
    s["p"] = {"password": 918273645}  # type: ignore[assignment]
    b = InMemoryChainBackend()
    e = await b.append(CHAIN, "policy.decision", "system", s, TS)
    (row,) = [x async for x in b.read(CHAIN)]
    blob = json.dumps(dict(row.payload))
    assert CANARY not in blob and "918273645" not in blob
    assert row.payload["headers"] == {"Authorization": "[redacted]"} and e.payload == row.payload


def test_pb4_prepare_payload_always_resanitizes() -> None:
    s = c.sanitize_payload({"a": "x\x00"})
    s["token"] = CANARY  # type: ignore[assignment]
    assert c.prepare_payload(s)["token"] == "[redacted]"


def test_pb4_idempotence_is_preserved_with_records_carried_over() -> None:
    once = c.sanitize_payload({"a": "x\x00y", "password": CANARY, "h": [["Cookie", CANARY]], "f": 1.5, "t": "A" * 5000})
    twice = c.sanitize_payload(once)
    assert twice == once and c.sanitize_payload(twice) == once
    assert once["sanitized"] is True and len(once["sanitization"]) >= 4  # type: ignore[arg-type]


def test_pb4_forged_records_on_a_returned_payload_are_whitelisted_not_trusted() -> None:
    s = c.sanitize_payload({"a": "x\x00y"})
    s["sanitization"] = [{"reason": "escaped", "path": "$.a", "evil": CANARY}, {"reason": CANARY}, "str", {"x": 1}]  # type: ignore[assignment]
    out = c.sanitize_payload(s)
    assert CANARY not in json.dumps(out)
    assert out["sanitization"] == [{"reason": "escaped", "path": "$.a"}]


# ------------------------------------------------------------------ PB-8
def _no_context(err: BaseException) -> None:
    assert err.__context__ is None and err.__cause__ is None


def test_pb8_signer_errors_have_no_context(tmp_path: Path) -> None:
    d = tmp_path / "k"
    d.mkdir(mode=0o700)
    bad = d / "junk.pem"
    fd = os.open(bad, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.write(fd, b"junk")
    os.close(fd)
    cases = [
        lambda: Ed25519FileSigner.load(d / "missing.pem"),
        lambda: Ed25519FileSigner.load(bad),
        lambda: Ed25519FileSigner.generate_to_file(bad),
        lambda: Ed25519PublicVerifier.from_hex("ab" * 31 + "zz"),
        lambda: Ed25519PublicVerifier.from_hex("00" * 32 + "0"),
    ]
    for case in cases:
        with pytest.raises(SignerKeyError) as info:
            case()
        _no_context(info.value)
