"""``guarded_head``: one recorded ALLOW, one HEAD, to our own stub, or nothing at all."""

from __future__ import annotations

import asyncio
import dataclasses
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from devpath import LABEL, transport
from devpath.stub import RunningStub

from vulnscope.policy.clock import SystemClock
from vulnscope.policy.denylist import compute_policy_version
from vulnscope.policy.ratelimit import InMemoryRateLimitStore
from vulnscope.policy.resolver import ResolutionError
from vulnscope.policy.types import Action, EngagementPolicyView, PolicyDecision, RuleId
from vulnscope.validate.types import HEADER_NAMES, HeaderResponse

CANARY = "canary-7f3a9c"


class FakeLedger:
    def __init__(self, events: list[str], fail: str | None = None) -> None:
        self.events = events
        self.fail = fail
        self.entries: list[dict[str, Any]] = []

    async def head(self, chain_id: str) -> None:
        self.events.append("head")
        if self.fail == "head":
            raise ConnectionError("ledger down")

    async def append(self, **kwargs: Any) -> SimpleNamespace:
        self.events.append("append")
        if self.fail == "append":
            raise ConnectionError("ledger down")
        self.entries.append(kwargs)
        return SimpleNamespace(seq=len(self.entries) - 1)  # seq 0 is a valid sequence number


def make_view(**changes: Any) -> EngagementPolicyView:
    now = datetime.now(UTC)
    values: dict[str, Any] = {
        "engagement_id": "eng-step1",
        "org_id": "org-step1",
        "profile": "lab",
        "status": "active",
        "scope_allow": ("127.0.0.1",),
        "scope_deny": (),
        "expected_ip_ranges": (),
        "rate_limit_rps": 5.0,
        "window_not_before": now - timedelta(minutes=1),
        "window_not_after": now + timedelta(hours=1),
        "policy_version": compute_policy_version(lab_enabled=True, lab_cidr=None),
    }
    values.update(changes)
    return EngagementPolicyView(**values)


class Harness:
    def __init__(self, *, ledger_fail: str | None = None, lab_enabled: bool = True) -> None:
        self.events: list[str] = []
        self.ledger = FakeLedger(self.events, ledger_fail)
        self.view_changes: dict[str, Any] = {}
        if not lab_enabled:
            self.view_changes["policy_version"] = compute_policy_version(
                lab_enabled=False, lab_cidr=None
            )
        self.deps = transport.TransportDeps(
            clock=SystemClock(),
            rate_limit_store=InMemoryRateLimitStore(),
            chain_backend=self.ledger,  # type: ignore[arg-type]
            lab_enabled=lab_enabled,
            lab_cidr=None,
        )

    async def fresh_view(self) -> EngagementPolicyView:
        self.events.append("view")
        return make_view(**self.view_changes)

    async def head(self, stub: Any, run_id: str = "run-1") -> Any:
        return await transport.guarded_head(
            stub=stub, fresh_view=self.fresh_view, deps=self.deps, run_id=run_id
        )


@pytest.fixture
def stub() -> Iterator[RunningStub]:
    with RunningStub("insecure") as running:
        yield running


@pytest.fixture
def connects(monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    """Records every socket the transport creates (and so every possible connect)."""
    seen: list[Any] = []
    real = transport._new_socket

    def spy() -> Any:
        sock = real()
        seen.append(sock)
        return sock

    monkeypatch.setattr(transport, "_new_socket", spy)
    return seen


def test_label_and_caps_are_pinned() -> None:
    assert LABEL == "STEP 1 DEVELOPMENT PATH: no gateway, no worker, not the security boundary"
    assert transport.TOTAL_TIMEOUT_S == 5.0
    assert transport.MAX_HEADER_BYTES == 16 * 1024
    assert transport.PINNED_HOST == "127.0.0.1"


async def test_allowed_head_sends_exactly_one_minimal_head(
    stub: RunningStub, connects: list[Any]
) -> None:
    h = Harness()
    decision, response = await h.head(stub)
    assert (decision.allowed, decision.rule_id, decision.ledger_seq) == (True, RuleId.ALLOW, 0)
    assert response == HeaderResponse(status=200, headers=())
    assert len(connects) == 1
    assert stub.connections_before_now() == 1
    assert stub.request_count == 1
    lines = stub.requests[0].split(b"\r\n")
    assert lines[0] == b"HEAD / HTTP/1.1"
    assert sorted(lines[1:]) == sorted(
        [b"", b"", f"Host: 127.0.0.1:{stub.port}".encode(), b"Connection: close"]
    )


async def test_fresh_view_is_read_immediately_before_each_decision(stub: RunningStub) -> None:
    h = Harness()
    await h.head(stub)
    allowed = ["view", "head", "append", "view"]  # the last read is the pre-send re-check
    assert h.events == allowed
    h.view_changes["status"] = "revoked"
    decision, response = await h.head(stub)
    assert h.events == allowed + ["view", "head", "append"]
    assert (decision.rule_id, response) == (RuleId.REVOKED, None)
    assert stub.connections_before_now() == 1


async def test_adapter_labels_the_decision_entry(stub: RunningStub) -> None:
    h = Harness()
    await h.head(stub, run_id="0192-abc")
    payload = h.ledger.entries[0]["payload"]
    assert payload["action"]["adapter"] == "devpath.security_headers@1|job=0192-abc"
    assert payload["action"]["is_redirect_hop"] is False
    assert h.ledger.entries[0]["kind"] == "policy.decision"


@pytest.mark.parametrize(
    ("changes", "rule"),
    [
        ({"status": "revoked"}, RuleId.REVOKED),
        ({"scope_allow": ("127.0.0.2",)}, RuleId.OUT_OF_SCOPE),
        ({"scope_deny": ("127.0.0.1",)}, RuleId.EXCLUDED),
    ],
)
async def test_deny_is_recorded_and_nothing_connects(
    stub: RunningStub, connects: list[Any], changes: dict[str, Any], rule: RuleId
) -> None:
    h = Harness()
    h.view_changes.update(changes)
    decision, response = await h.head(stub)
    assert (decision.allowed, decision.rule_id, response) == (False, rule, None)
    assert [e["payload"]["rule_id"] for e in h.ledger.entries] == [rule.value]
    assert connects == []
    assert stub.connections_before_now() == 0


async def test_lab_not_enabled_denies_without_connecting(
    stub: RunningStub, connects: list[Any]
) -> None:
    decision, response = await Harness(lab_enabled=False).head(stub)
    assert (decision.allowed, response) == (False, None)
    assert connects == []
    assert stub.connections_before_now() == 0


@pytest.mark.parametrize("failing", ["head", "append"])
async def test_ledger_failure_raises_and_nothing_connects(
    stub: RunningStub, connects: list[Any], failing: str
) -> None:
    with pytest.raises(ConnectionError):
        await Harness(ledger_fail=failing).head(stub)
    assert connects == []
    assert stub.connections_before_now() == 0


def _tamper(monkeypatch: pytest.MonkeyPatch, **changes: Any) -> None:
    """A decision that did not come out as expected must be refused by the sender itself."""
    real = transport.decide_and_record

    async def fake(*args: Any, **kwargs: Any) -> PolicyDecision:
        decision = await real(*args, **kwargs)
        action_changes = changes.get("action")
        fields = {k: v for k, v in changes.items() if k != "action"}
        if action_changes:
            fields["action"] = dataclasses.replace(decision.action, **action_changes)
        return dataclasses.replace(decision, **fields)

    monkeypatch.setattr(transport, "decide_and_record", fake)


@pytest.mark.parametrize(
    ("changes", "code"),
    [
        ({"ledger_seq": None}, "not_recorded"),
        ({"rule_id": RuleId.OUT_OF_SCOPE}, "not_an_allow"),
        ({"resolved_ips": ("127.0.0.2",)}, "address_not_pinned"),
        ({"resolved_ips": ("::1",)}, "address_not_pinned"),
        ({"resolved_ips": ("10.0.0.1",)}, "address_not_pinned"),
        ({"resolved_ips": ("169.254.169.254",)}, "address_not_pinned"),
        ({"resolved_ips": ("127.0.0.1", "127.0.0.2")}, "address_not_pinned"),
        ({"resolved_ips": ()}, "address_not_pinned"),
    ],
)
async def test_sender_refuses_a_tampered_decision(
    stub: RunningStub,
    connects: list[Any],
    monkeypatch: pytest.MonkeyPatch,
    changes: dict[str, Any],
    code: str,
) -> None:
    _tamper(monkeypatch, **changes)
    with pytest.raises(transport.SendRefused) as caught:
        await Harness().head(stub)
    assert caught.value.code == code
    assert connects == []
    assert stub.connections_before_now() == 0


@pytest.mark.parametrize(
    "action_changes",
    [
        {"target": "http://127.0.0.1:1/"},
        {"is_redirect_hop": True},
        {"adapter": "other@1"},
    ],
)
async def test_sender_refuses_a_decision_for_another_action(
    stub: RunningStub,
    connects: list[Any],
    monkeypatch: pytest.MonkeyPatch,
    action_changes: dict[str, Any],
) -> None:
    _tamper(monkeypatch, action=action_changes)
    with pytest.raises(transport.SendRefused) as caught:
        await Harness().head(stub)
    assert caught.value.code == "action_mismatch"
    assert connects == []


def _allow(target: str, ips: tuple[str, ...] = ("127.0.0.1",), hop: bool = False) -> PolicyDecision:
    return PolicyDecision(
        allowed=True,
        reason="allowed",
        rule_id=RuleId.ALLOW,
        policy_version="v",
        action=Action(kind="http", target=target, adapter="a", is_redirect_hop=hop),
        resolved_ips=ips,
        ts=datetime.now(UTC),
        ledger_seq=0,
    )


def test_pin_accepts_only_the_exact_stub_origin() -> None:
    assert transport._refusal(_allow("http://127.0.0.1:4000/"), 4000) is None


@pytest.mark.parametrize(
    ("decision", "code"),
    [
        (_allow("https://127.0.0.1:4000/"), "scheme_not_pinned"),
        (_allow("http://localhost:4000/"), "host_not_pinned"),
        (_allow("http://127.0.0.2:4000/"), "host_not_pinned"),
        (_allow("http://[::1]:4000/", ("::1",)), "host_not_pinned"),
        (_allow("http://127.0.0.1:5432/"), "port_not_pinned"),
        (_allow("http://127.0.0.1/"), "port_not_pinned"),
        (_allow("http://127.0.0.1:4000/", hop=True), "redirect_hop"),
        (_allow("not a url"), "target_unparseable"),
        (dataclasses.replace(_allow("http://127.0.0.1:4000/"), allowed=False), "not_an_allow"),
    ],
)
def test_pin_refuses_everything_else(decision: PolicyDecision, code: str) -> None:
    assert transport._refusal(decision, 4000) == code


async def test_port_must_still_be_the_running_stubs_after_the_decision(
    stub: RunningStub, connects: list[Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    reads = iter([40001, 40002])
    monkeypatch.setattr(transport, "bound_port", lambda _stub: next(reads))
    with pytest.raises(transport.SendRefused) as caught:
        await Harness().head(stub)
    assert caught.value.code == "port_not_pinned"
    assert connects == []


async def test_stopped_stub_is_not_contacted_and_nothing_is_decided(connects: list[Any]) -> None:
    running = RunningStub("insecure")
    running.close()
    h = Harness()
    with pytest.raises(transport.SendRefused) as caught:
        await h.head(running)
    assert caught.value.code == "stub_not_running"
    assert (h.events, connects) == ([], [])


async def test_stub_stopped_during_the_decision_is_not_contacted(
    connects: list[Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    with RunningStub("insecure") as running:
        real = transport.decide_and_record

        async def stop_then_return(*args: Any, **kwargs: Any) -> PolicyDecision:
            decision = await real(*args, **kwargs)
            running.close()
            return decision

        monkeypatch.setattr(transport, "decide_and_record", stop_then_return)
        with pytest.raises(transport.SendRefused) as caught:
            await Harness().head(running)
    assert caught.value.code == "stub_not_running"
    assert connects == []


def test_resolver_refuses_every_name() -> None:
    with pytest.raises(ResolutionError):
        transport._RefusingResolver().resolve("localhost")


async def test_no_dns_and_no_environment_proxy(
    stub: RunningStub, monkeypatch: pytest.MonkeyPatch
) -> None:
    def no_dns(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("DNS lookup attempted")

    monkeypatch.setattr("socket.getaddrinfo", no_dns)
    with RunningStub("secure") as trap:
        for name in ("HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
            monkeypatch.setenv(name, f"http://127.0.0.1:{trap.port}")
        _, response = await Harness().head(stub)
        assert response is not None
        assert stub.request_count == 1
        monkeypatch.undo()
        assert trap.connections_before_now() == 0


async def test_only_allowlisted_header_names_are_kept_and_no_value() -> None:
    raw = (
        b"HTTP/1.1 200 OK\r\nX-Frame-Options: " + CANARY.encode() + b"\r\n"
        b"Set-Cookie: " + CANARY.encode() + b"\r\nX-" + CANARY.encode() + b": 1\r\n"
        b"Referrer-Policy:\r\nContent-Length: 0\r\n\r\n"
    )
    with RunningStub(raw_response=raw) as running:
        _, response = await Harness().head(running)
    assert response is not None
    assert response.headers == ((b"x-frame-options", b""), (b"referrer-policy", b""))
    assert CANARY not in repr(response)


async def test_secure_mode_reports_all_five_names() -> None:
    with RunningStub("secure") as running:
        _, response = await Harness().head(running)
    assert response is not None
    assert sorted(n.decode() for n, _ in response.headers) == sorted(HEADER_NAMES)


async def test_redirect_is_not_followed_and_location_is_not_returned() -> None:
    with RunningStub("redirect") as running:
        h = Harness()
        _, response = await h.head(running)
        assert response == HeaderResponse(status=302, headers=())
        assert running.connections_before_now() == 1
        assert running.request_count == 1
    assert len(h.ledger.entries) == 1  # no hop decision (round 25)
    assert "169.254" not in repr(h.ledger.entries)


async def _expect_failure(raw: bytes) -> transport.SendFailed:
    with RunningStub(raw_response=raw) as running:
        with pytest.raises(transport.SendFailed) as caught:
            await Harness().head(running)
    return caught.value


def _sized_response(total: int) -> bytes:
    start, end = b"HTTP/1.1 200 OK\r\nX-Pad: ", b"\r\n\r\n"
    return start + b"a" * (total - len(start) - len(end)) + end


async def test_headers_at_the_cap_are_accepted() -> None:
    with RunningStub(raw_response=_sized_response(16 * 1024)) as running:
        _, response = await Harness().head(running)
    assert response == HeaderResponse(status=200, headers=())


@pytest.mark.parametrize(
    "raw",
    [
        _sized_response(16 * 1024 + 1),
        _sized_response(200_000),
        b"HTTP/1.1 100 Continue\r\n\r\n" * 2000 + b"HTTP/1.1 200 OK\r\n\r\n",
    ],
    ids=["one-over", "huge", "endless-informational"],
)
async def test_header_cap(raw: bytes) -> None:
    failure = await _expect_failure(raw)
    assert failure.code == "headers_too_large"
    assert failure.decision.ledger_seq == 0


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"HTTP/1.1 200 OK\r\nX-Frame-Options: DENY",
        CANARY.encode() + b"\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nbad header " + CANARY.encode() + b"\r\n\r\n",
        b"HTTP/1.1 101 Switching Protocols\r\n\r\n",
    ],
    ids=["empty", "truncated", "garbage", "bad-header", "switching-protocols"],
)
async def test_protocol_errors_carry_no_target_bytes(raw: bytes) -> None:
    failure = await _expect_failure(raw)
    assert failure.code == "protocol_error"
    assert CANARY not in str(failure) + repr(failure)
    assert failure.__cause__ is None
    assert failure.__context__ is None


async def test_total_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(transport, "TOTAL_TIMEOUT_S", 0.2)
    with RunningStub("stall") as running:
        started = asyncio.get_running_loop().time()
        with pytest.raises(transport.SendFailed) as caught:
            await Harness().head(running)
        assert asyncio.get_running_loop().time() - started < 2.0
        assert caught.value.code == "timeout"
        assert await asyncio.to_thread(running.wait_for_client_close)


async def test_cancelling_the_task_stops_the_send_and_closes_the_socket(
    connects: list[Any],
) -> None:
    """The seam for the in-flight revoke watcher: run it as a task and cancel it."""
    with RunningStub("stall") as running:
        task = asyncio.create_task(Harness().head(running))
        assert await asyncio.to_thread(running.wait_for_requests, 1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert await asyncio.to_thread(running.wait_for_client_close)
    assert [s.fileno() for s in connects] == [-1]


def _after_record(h: Harness, change: Any) -> None:
    """``change`` runs once the decision is in the ledger, before the sender resumes."""
    real = h.ledger.append

    async def append(**kwargs: Any) -> Any:
        entry = await real(**kwargs)
        change()
        return entry

    h.ledger.append = append  # type: ignore[method-assign]


async def _refused_code(h: Harness, stub: RunningStub, sending: asyncio.Event) -> str:
    try:
        await transport.guarded_head(
            stub=stub, fresh_view=h.fresh_view, deps=h.deps, run_id="run-1", sending=sending
        )
    except transport.SendRefused as refused:
        assert refused.__context__ is None and refused.__cause__ is None
        assert CANARY not in str(refused) + repr(refused)
        assert refused.decision is not None and refused.decision.ledger_seq == 0
        return refused.code
    return "sent"


def _nothing_sent(stub: RunningStub, connects: list[Any]) -> tuple[int, int, int]:
    return (len(connects), stub.connections_before_now(), stub.request_count)


@pytest.mark.parametrize(
    ("changes", "code"),
    [
        (lambda: {"status": "revoked"}, "revoked_before_send"),
        (lambda: {"status": "draft"}, "revoked_before_send"),
        (
            lambda: {"window_not_after": datetime.now(UTC) - timedelta(microseconds=1)},
            "window_closed_before_send",
        ),
        (
            lambda: {"window_not_before": datetime.now(UTC) + timedelta(hours=1)},
            "window_closed_before_send",
        ),
    ],
    ids=["revoked", "not-active", "window-expired", "window-not-open"],
)
async def test_change_during_decision_recording_sends_nothing(
    stub: RunningStub, connects: list[Any], changes: Any, code: str
) -> None:
    h = Harness()
    _after_record(h, lambda: h.view_changes.update(changes()))
    sending = asyncio.Event()
    got = await _refused_code(h, stub, sending)
    assert (got, _nothing_sent(stub, connects)) == (code, (0, 0, 0))
    assert not sending.is_set()
    assert [e["payload"]["rule_id"] for e in h.ledger.entries] == ["ALLOW"]


@pytest.mark.parametrize("fault", ["error", "timeout", "unusable"])
async def test_failed_recheck_fails_closed(
    stub: RunningStub, connects: list[Any], monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    monkeypatch.setattr(transport, "RECHECK_TIMEOUT_S", 0.1, raising=False)
    h = Harness()
    real = h.fresh_view
    reads: list[int] = []

    async def fresh_view() -> Any:
        reads.append(1)
        if len(reads) == 1:
            return await real()
        if fault == "error":
            raise ConnectionError(CANARY)
        if fault == "timeout":
            await asyncio.sleep(1.0)
            return await real()
        return None

    h.fresh_view = fresh_view  # type: ignore[method-assign]
    got = await asyncio.wait_for(_refused_code(h, stub, asyncio.Event()), 3.0)
    assert (got, _nothing_sent(stub, connects)) == ("recheck_failed", (0, 0, 0))


def test_recheck_timeout_is_pinned() -> None:
    assert transport.RECHECK_TIMEOUT_S == 2.0
