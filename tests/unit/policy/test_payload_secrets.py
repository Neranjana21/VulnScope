"""PA-1 (rule 6): no credential in a target ever reaches the ledger payload."""

from __future__ import annotations

import hashlib
import json

import pytest
from policy_test_support import run_decide

from vulnscope.policy.decide_and_record import policy_decision_to_payload

SECRETS = ("S3cretPw", "KEY-123abc", "TOKEN-xyz789")
H = "a.lab.test"
TARGETS = [
    f"https://user:{SECRETS[0]}@a.lab.test/p",  # unparseable (userinfo)
    f"https://a.lab.test/p?api_key={SECRETS[1]}",  # allowed
    f"https://a.lab.test/p#access_token={SECRETS[2]}",  # allowed
    f"https://a.lab.test:8443/?api_key={SECRETS[1]}#access_token={SECRETS[2]}",
    f"https://other.test/?api_key={SECRETS[1]}",  # denied: out of scope
    f"ftp://u:{SECRETS[0]}@a.lab.test/?k={SECRETS[1]}",  # unparseable scheme
    f"a b?api_key={SECRETS[1]}",  # unparseable
]


@pytest.mark.parametrize("target", TARGETS)
def test_no_secret_substring_in_serialized_payload(target: str) -> None:
    d, _ = run_decide(target, allow=(H,), table={H: ("192.0.2.1",)})
    p = policy_decision_to_payload(d)
    blob = json.dumps(p)
    for secret in SECRETS:
        assert secret not in blob
    assert "api_key" not in blob and "access_token" not in blob and "user:" not in blob
    assert p["action"]["target_sha256"] == hashlib.sha256(target.encode()).hexdigest()  # type: ignore[index]


def test_allow_deny_unparseable_shapes() -> None:
    allowed, _ = run_decide(TARGETS[1], allow=(H,), table={H: ("192.0.2.1",)})
    denied, _ = run_decide(TARGETS[4], allow=(H,))
    bad, _ = run_decide(TARGETS[0], allow=(H,))
    assert allowed.allowed and not denied.allowed and not bad.allowed
    pa = policy_decision_to_payload(allowed)["action"]
    assert (pa["scheme"], pa["host"], pa["port"]) == ("https", H, 443)  # type: ignore[index]
    pd = policy_decision_to_payload(denied)["action"]
    assert pd["host"] == "other.test"  # type: ignore[index]
    pb = policy_decision_to_payload(bad)["action"]
    assert pb["target_unparseable"] is True  # type: ignore[index]
    assert pb["target_length"] == len(TARGETS[0])  # type: ignore[index]
    assert "host" not in pb and "target" not in pb  # type: ignore[operator]


def test_lone_surrogate_target_hashes_without_raising() -> None:
    d, _ = run_decide("a\ud800b", allow=(H,))
    p = policy_decision_to_payload(d)
    assert p["action"]["target_unparseable"] is True  # type: ignore[index]
    assert len(p["action"]["target_sha256"]) == 64  # type: ignore[arg-type,index]
