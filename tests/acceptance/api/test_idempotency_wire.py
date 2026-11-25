"""Idempotency on the wire (design 12.4, PD-18) and the revoke-memo namespace finding (DE-01)."""
from __future__ import annotations

import time

import pytest
from acc_support import SCAN_PAYLOAD, World, assert_problem, engagement_payload

pytestmark = pytest.mark.acceptance


@pytest.mark.covers_code("IDEMPOTENCY_CONFLICT")
def test_same_key_same_body_replays_and_different_body_conflicts(world: World) -> None:
    a = world.org("admin")
    p = engagement_payload()
    r1 = world.create(a, p, key="idem-a")
    r2 = world.create(a, p, key="idem-a")
    assert r1.status_code == r2.status_code == 201 and r1.json() == r2.json()
    assert "idempotent-replayed" not in r1.headers
    assert r2.headers["idempotent-replayed"] == "true"
    assert r1.headers["x-request-id"] != r2.headers["x-request-id"]
    eid = r1.json()["id"]
    assert len(world.ledger_rows(f"engagement:{eid}")) == 1
    assert world.engagements_of(a.org_id) == 1

    other = engagement_payload()
    assert_problem(world.create(a, other, key="idem-a"), 409, "IDEMPOTENCY_CONFLICT")
    assert world.engagements_of(a.org_id) == 1  # first resource unchanged

    # the same key on a different path is a conflict too
    assert_problem(world.post(f"/v1/engagements/{eid}/scans", a, SCAN_PAYLOAD, key="idem-a"),
                   409, "IDEMPOTENCY_CONFLICT")


def test_no_key_twice_gives_two_resources(world: World) -> None:
    a = world.org("admin")
    p = engagement_payload()
    assert world.create(a, p).json()["id"] != world.create(a, p).json()["id"]
    assert world.engagements_of(a.org_id) == 2


def test_same_key_same_invalid_body_replays_one_intake_entry(world: World) -> None:
    a = world.org("admin")
    p = engagement_payload()
    p["authorization"]["confirmed"] = False
    r1 = world.create(a, p, key="idem-bad")
    r2 = world.create(a, p, key="idem-bad")
    b1 = assert_problem(r1, 422, "AUTH_NOT_CONFIRMED")
    b2 = assert_problem(r2, 422, "AUTH_NOT_CONFIRMED")
    assert b1["ledger_seq"] == b2["ledger_seq"]
    assert {k: v for k, v in b1.items() if k != "request_id"} == {
        k: v for k, v in b2.items() if k != "request_id"}
    assert r2.headers.get("idempotent-replayed") == "true"
    assert len(world.ledger_rows(a.intake)) == 1


def test_key_syntax_is_enforced(world: World) -> None:
    a = world.org("admin")
    for bad in ("", "has space", "k" * 256, "tab\there"):
        try:
            r = world.create(a, key=bad)
        except Exception:  # noqa: BLE001 - the HTTP client may refuse the header itself
            continue
        assert_problem(r, 422, "INVALID_REQUEST")
    assert world.create(a, key="k" * 255).status_code == 201


def test_revoke_retry_after_a_client_key_shaped_like_the_memo_key_still_returns_original(
        world: World) -> None:
    """DE-01 (owner-approved spec). Client keys with the prefixes ``revoke-record:`` or
    ``revoke-memo-`` (case-insensitive) are reserved: a create route rejects them with 422
    INVALID_REQUEST and writes nothing, so a client can never occupy the revoke memo row. A plain
    revoke retry (AC7 point 4: 'second revoke returns the original body') still returns the
    original body without a claim-wait 503."""
    a = world.org("assessor")
    eid = world.create(a).json()["id"]
    n_eng, n_idem = world.engagements_of(a.org_id), world.idem_rows(a.org_id)
    n_intake = len(world.ledger_rows(a.intake))
    n_chain = len(world.ledger_rows(f"engagement:{eid}"))
    for reserved in (f"revoke-record:{eid}", f"REVOKE-RECORD:{eid}", "revoke-memo-v1:x",
                     "Revoke-Memo-x"):
        assert_problem(world.create(a, key=reserved), 422, "INVALID_REQUEST")
    assert world.engagements_of(a.org_id) == n_eng  # no write at all
    assert world.idem_rows(a.org_id) == n_idem
    assert len(world.ledger_rows(a.intake)) == n_intake
    assert len(world.ledger_rows(f"engagement:{eid}")) == n_chain
    first = world.post(f"/v1/engagements/{eid}/revoke", a, {"reason": "t"})
    assert first.status_code == 200
    t0 = time.monotonic()
    again = world.post(f"/v1/engagements/{eid}/revoke", a, {"reason": "t2"})
    assert again.status_code == 200 and again.json() == first.json()
    assert time.monotonic() - t0 < 3.0  # never a 10 s wait followed by a 503


def test_revoke_ignores_idempotency_key_and_stays_naturally_idempotent(world: World) -> None:
    """DE-02 (spec amended, io-contracts: revoke is naturally idempotent and ignores
    Idempotency-Key). A revoke WITH a header gives the same outcome as one without, creates no
    row keyed by the client key, never conflicts with a create that used the same key, and a
    repeated revoke returns the original body."""
    a = world.org("admin")
    e_key = world.create(a, key="k-create-revoke").json()["id"]
    e_plain = world.create(a).json()["id"]
    rows0 = world.idem_rows(a.org_id)
    r_plain = world.post(f"/v1/engagements/{e_plain}/revoke", a, {"reason": "t"})
    rows_plain = world.idem_rows(a.org_id) - rows0
    rows1 = world.idem_rows(a.org_id)
    r_key = world.post(f"/v1/engagements/{e_key}/revoke", a, {"reason": "t"},
                       key="k-create-revoke")
    rows_key = world.idem_rows(a.org_id) - rows1
    assert r_plain.status_code == r_key.status_code == 200
    assert set(r_plain.json()) == set(r_key.json())  # same shape, no 409 problem body
    assert rows_key == rows_plain  # only the recorder's own memo row, nothing keyed by the header
    # a repeated revoke (same key with another reason, and a new key) returns the original body
    again = world.post(f"/v1/engagements/{e_key}/revoke", a, {"reason": "t2"},
                       key="k-create-revoke")
    other = world.post(f"/v1/engagements/{e_key}/revoke", a, {"reason": "t3"}, key="another-key")
    assert again.status_code == other.status_code == 200
    assert again.json() == other.json() == r_key.json()
    assert world.idem_rows(a.org_id) == rows1 + rows_key  # repeats add no rows
    assert len(world.ledger_rows(f"engagement:{e_key}")) == 2  # create + exactly one revoke


@pytest.fixture
def tight_auth_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """One shared and one reserved auth slot with a 50 ms queue wait
    (config.load_admission_overrides). Request it BEFORE ``world``: the lifespan reads the
    environment at startup."""
    monkeypatch.setenv("VULNSCOPE_API_AUTH_INFLIGHT", "1")
    monkeypatch.setenv("VULNSCOPE_API_AUTH_RESERVED", "1")
    monkeypatch.setenv("VULNSCOPE_API_AUTH_QUEUE_WAIT_S", "0.05")


def test_auth_shed_is_503_with_numeric_retry_after_and_revoke_stays_reachable(
        tight_auth_env: None, world: World) -> None:
    """Verifier P3-1 (BL-DE-1): deterministic shed path. The only shared auth slot is held (the
    semaphore is drained directly, no timing race), so a non-revoke call is shed after the queue
    wait with 503 UNAVAILABLE and a numeric Retry-After, while revoke uses the reserved slot."""
    a = world.org("admin")
    eid = world.create(a).json()["id"]
    sem = world.app.state.d.gates.auth._shared
    held = sem._value
    sem._value = 0
    try:
        t0 = time.monotonic()
        shed = world.get(f"/v1/engagements/{eid}", a)
        waited = time.monotonic() - t0
        assert_problem(shed, 503, "UNAVAILABLE")
        assert shed.headers["retry-after"].isdigit() and int(shed.headers["retry-after"]) >= 1
        assert waited < 3.0  # a fast shed, not a hang
        ok = world.post(f"/v1/engagements/{eid}/revoke", a, {"reason": "t"})
        assert ok.status_code == 200  # N-03: the reserved slot keeps revocation reachable
    finally:
        sem._value = held
    assert world.get(f"/v1/engagements/{eid}", a).status_code == 200  # recovers once released
