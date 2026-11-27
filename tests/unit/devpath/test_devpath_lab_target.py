"""ADR-0014: the sender's target allowlist. Refusal tests.

Forged ALLOW decisions are fed to the sender, so the pin is tested without the policy.
In every refusal test the sender's socket factory is a tripwire (so nothing can connect
even if the pin were broken) and an audit hook counts every ``socket()`` and connect.
"""

from __future__ import annotations

import ast
import asyncio
import copy
import dataclasses
import pickle
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from devpath import targets, transport
from devpath.stub import RunningStub
from lab_fake import FakeLabApp
from test_devpath_transport import Harness

from vulnscope.policy.decide_and_record import decide_and_record
from vulnscope.policy.types import Action, PolicyDecision, RuleId

DEVPATH = Path(__file__).resolve().parents[3] / "devpath"
JUICE_URL = "http://127.0.0.1:3000/"

_EVENTS: list[str] = []
_COUNTING = [False]


def _count(event: str, args: tuple[Any, ...]) -> None:
    if _COUNTING[0] and event in ("socket.__new__", "socket.connect", "socket.getaddrinfo"):
        _EVENTS.append(event)


sys.addaudithook(_count)  # cannot be removed; inert unless _COUNTING is set


@contextmanager
def no_network(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Asserts zero socket() calls and zero connects inside the block."""
    attempts: list[int] = []

    def tripwire() -> Any:
        attempts.append(1)
        raise AssertionError("the sender tried to create a socket")

    monkeypatch.setattr(transport, "_new_socket", tripwire)
    _EVENTS.clear()
    _COUNTING[0] = True
    try:
        yield
    finally:
        _COUNTING[0] = False
        assert (attempts, _EVENTS) == ([], [])


@pytest.fixture
def stub() -> Iterator[RunningStub]:
    with RunningStub("insecure") as running:
        yield running


def forged(
    target: str,
    ips: tuple[str, ...] = ("127.0.0.1",),
    *,
    hop: bool = False,
    kind: Any = "http",
    adapter: str = "a",
) -> PolicyDecision:
    return PolicyDecision(
        allowed=True,
        reason="allowed",
        rule_id=RuleId.ALLOW,
        policy_version="v",
        action=Action(kind=kind, target=target, adapter=adapter, is_redirect_hop=hop),
        resolved_ips=ips,
        ts=datetime.now(UTC),
        ledger_seq=0,
    )


def bad_decisions(good_port: int, other_port: int) -> dict[str, PolicyDecision]:
    """``other_port`` belongs to the other allowlisted target. Keys do not depend on ports."""
    good = f"http://127.0.0.1:{good_port}/"
    ports = {str(p): p for p in (0, 80, 3001, 5432, 65536)}
    ports |= {"other-target": other_port, "good-plus-1": good_port + 1}
    cases = {f"port-{k}": forged(f"http://127.0.0.1:{p}/") for k, p in ports.items()}
    cases["port-missing"] = forged("http://127.0.0.1/")
    cases["port-leading-zero"] = forged(f"http://127.0.0.1:0{good_port}/")
    for host, ip in (
        ("127.0.0.2", "127.0.0.2"),
        ("0.0.0.0", "0.0.0.0"),
        ("[::1]", "::1"),
        ("[::ffff:127.0.0.1]", "::ffff:127.0.0.1"),
        ("10.0.0.5", "10.0.0.5"),
        ("169.254.169.254", "169.254.169.254"),
    ):
        url = f"http://{host}:{good_port}/"
        cases[f"host-{host}"] = forged(url, (ip,))
        cases[f"host-{host}-lying-ips"] = forged(url)
    for form in (
        "localhost",
        "localhost.",
        "host.docker.internal",
        "127.1",
        "2130706433",
        "0x7f000001",
        "127.0.0.1.",
        "user@127.0.0.1",
        "user:pw@127.0.0.1",
        "127.0.0.1@127.0.0.1",
    ):
        cases[f"form-{form}"] = forged(f"http://{form}:{good_port}/")
    cases["https"] = forged(f"https://127.0.0.1:{good_port}/")
    cases["scheme-upper"] = forged(f"HTTP://127.0.0.1:{good_port}/")
    for name, ips in (
        ("empty", ()),
        ("other", ("127.0.0.2",)),
        ("v6", ("::1",)),
        ("two", ("127.0.0.1", "127.0.0.1")),
        ("metadata", ("169.254.169.254",)),
    ):
        cases[f"ips-{name}"] = forged(good, ips)
    for tail in ("/ftp", "/?q=1", "/#f", "", "//", "/."):
        cases[f"path-[{tail}]"] = forged(f"http://127.0.0.1:{good_port}{tail}")
    cases["kind-not-http"] = forged(good, kind="dns")
    cases["redirect-hop"] = forged(good, hop=True)
    cases["not-recorded"] = dataclasses.replace(forged(good), ledger_seq=None)
    cases["denied"] = dataclasses.replace(forged(good), allowed=False)
    cases["other-rule"] = dataclasses.replace(forged(good), rule_id=RuleId.OUT_OF_SCOPE)
    return cases


CASE_NAMES = sorted(bad_decisions(40000, 3000))


@pytest.mark.parametrize("name", CASE_NAMES)
@pytest.mark.parametrize("which", ["juice", "stub"])
async def test_a_forged_allow_never_reaches_a_socket(
    stub: RunningStub, monkeypatch: pytest.MonkeyPatch, which: str, name: str
) -> None:
    """Includes the cross cases: stub target with a port 3000 decision, and the reverse."""
    if which == "juice":
        target: Any = targets.JUICE_SHOP
        decision = bad_decisions(3000, stub.port)[name]
    else:
        target = stub
        decision = bad_decisions(stub.port, 3000)[name]
    sending = asyncio.Event()
    with no_network(monkeypatch):
        with pytest.raises(transport.SendRefused):
            await transport._pinned_send(target, decision, sending)
    assert not sending.is_set()


def test_the_pin_accepts_exactly_one_string_per_port() -> None:
    assert transport._refusal(forged(JUICE_URL), 3000) is None
    assert transport._refusal(forged("http://127.1:3000/"), 3000) == "target_not_exact"
    assert transport._refusal(forged(JUICE_URL, kind="dns"), 3000) == "kind_not_pinned"


def _tamper(monkeypatch: pytest.MonkeyPatch, change: Any) -> None:
    real = transport.decide_and_record

    async def fake(*args: Any, **kwargs: Any) -> PolicyDecision:
        return change(await real(*args, **kwargs))

    monkeypatch.setattr(transport, "decide_and_record", fake)


@pytest.mark.parametrize("name", CASE_NAMES)
async def test_a_forged_allow_from_the_decision_call_is_refused_for_the_lab_app(
    monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    """Same inputs through the public entry point (only the decision is forged)."""
    bad = bad_decisions(3000, 40000)[name]
    _tamper(monkeypatch, lambda real: dataclasses.replace(bad, ts=real.ts))
    with no_network(monkeypatch):
        if bad.allowed:
            with pytest.raises(transport.SendRefused):
                await Harness().head(targets.JUICE_SHOP)
        else:  # a deny is returned as it is, with nothing sent
            _, response = await Harness().head(targets.JUICE_SHOP)
            assert response is None


class _Sub(targets.LabTarget):
    pass


class _Equal(targets.LabTarget):
    def __eq__(self, other: object) -> bool:
        return True

    __hash__ = object.__hash__


class _Liar:
    port = 3000

    @property
    def __class__(self) -> type:
        return targets.LabTarget


FAKES = {
    "new-instance": lambda: targets.LabTarget(),
    "copy": lambda: copy.copy(targets.JUICE_SHOP),
    "deepcopy": lambda: copy.deepcopy(targets.JUICE_SHOP),
    "pickled": lambda: pickle.loads(pickle.dumps(targets.JUICE_SHOP)),
    "subclass": _Sub,
    "equal-instance": _Equal,
    "class-spoof": _Liar,
    "none": lambda: None,
    "name": lambda: "JUICE_SHOP",
    "port-number": lambda: 3000,
    "url": lambda: JUICE_URL,
    "class-object": lambda: targets.LabTarget,
}


@pytest.mark.parametrize("fake", FAKES)
async def test_a_fake_lab_target_is_refused_before_any_read(
    monkeypatch: pytest.MonkeyPatch, fake: str
) -> None:
    target = FAKES[fake]()
    assert target is not targets.JUICE_SHOP
    harness = Harness()
    with no_network(monkeypatch):
        with pytest.raises(transport.SendRefused) as caught:
            await harness.head(target)
        with pytest.raises(transport.SendRefused):
            await transport._pinned_send(target, forged(JUICE_URL), None)
    assert caught.value.code == "not_the_real_stub"
    assert (harness.events, harness.ledger.entries) == ([], [])


def test_the_lab_target_carries_no_state() -> None:
    with pytest.raises(AttributeError):
        targets.JUICE_SHOP.port = 5432  # type: ignore[attr-defined]
    assert targets.JUICE_SHOP_PORT == 3000


@pytest.mark.parametrize(
    ("changes", "rule"),
    [
        ({"status": "revoked"}, RuleId.REVOKED),
        ({"scope_allow": ("127.0.0.2",)}, RuleId.OUT_OF_SCOPE),
        ({"scope_deny": ("127.0.0.1",)}, RuleId.EXCLUDED),
    ],
)
async def test_a_denial_for_the_lab_app_is_recorded_and_nothing_is_sent(
    monkeypatch: pytest.MonkeyPatch, changes: dict[str, Any], rule: RuleId
) -> None:
    harness = Harness()
    harness.view_changes.update(changes)
    with no_network(monkeypatch):
        decision, response = await harness.head(targets.JUICE_SHOP)
    assert (decision.rule_id, response, decision.action.target) == (rule, None, JUICE_URL)
    assert [e["payload"]["rule_id"] for e in harness.ledger.entries] == [rule.value]


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.2:3000/",
        "http://0.0.0.0:3000/",
        "http://[::1]:3000/",
        "http://10.0.0.5:3000/",
        "http://169.254.169.254:3000/",
        "http://localhost:3000/",
        "http://localhost.:3000/",
        "http://host.docker.internal:3000/",
        "http://user@127.0.0.1:3000/",
        "http://127.0.0.1:65536/",
    ],
)
async def test_the_real_policy_denial_is_recorded(url: str) -> None:
    """No sender involved: the policy itself denies these, and the ledger holds it."""
    harness = Harness()
    deps = harness.deps
    decision = await decide_and_record(
        Action(kind="http", target=url, adapter="a"),
        await harness.fresh_view(),
        deps.clock.now(),
        resolver=transport._RefusingResolver(),
        clock=deps.clock,
        rate_limit_store=deps.rate_limit_store,
        chain_backend=deps.chain_backend,
        actor="system",
        lab_enabled=True,
        lab_cidr=None,
    )
    assert decision.allowed is False and decision.ledger_seq == 0
    assert [e["payload"]["allowed"] for e in harness.ledger.entries] == [False]


# --- the allowed send, against a listener this test owns ---


async def test_one_minimal_head_to_the_lab_app() -> None:
    with FakeLabApp() as app:
        decision, response = await Harness().head(targets.JUICE_SHOP)
    assert (decision.allowed, decision.action.target) == (True, JUICE_URL)
    assert response is not None and response.status == 200
    [request] = app.requests
    lines = request.split(b"\r\n")
    assert lines[0] == b"HEAD / HTTP/1.1"
    assert sorted(lines[1:]) == sorted([b"", b"", b"Host: 127.0.0.1:3000", b"Connection: close"])


async def test_a_redirect_from_the_lab_app_is_not_followed() -> None:
    with RunningStub("secure") as second:
        raw = (
            f"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{second.port}/\r\n"
            "Content-Length: 0\r\n\r\n"
        ).encode()
        harness = Harness()
        with FakeLabApp(raw) as app:
            _, response = await harness.head(targets.JUICE_SHOP)
        assert second.connections_before_now() == 0
    assert response is not None and (response.status, response.headers) == (302, ())
    assert len(app.requests) == 1
    assert len(harness.ledger.entries) == 1


@pytest.mark.parametrize(
    ("changes", "code"),
    [
        (lambda: {"status": "revoked"}, "revoked_before_send"),
        (
            lambda: {"window_not_after": datetime.now(UTC) - timedelta(microseconds=1)},
            "window_closed_before_send",
        ),
    ],
)
async def test_the_pre_send_recheck_applies_to_the_lab_app(
    monkeypatch: pytest.MonkeyPatch, changes: Any, code: str
) -> None:
    harness = Harness()
    real = harness.ledger.append

    async def append(**kwargs: Any) -> Any:
        entry = await real(**kwargs)
        harness.view_changes.update(changes())
        return entry

    harness.ledger.append = append  # type: ignore[method-assign]
    with no_network(monkeypatch):
        with pytest.raises(transport.SendRefused) as caught:
            await harness.head(targets.JUICE_SHOP)
    assert caught.value.code == code


# --- structure ---


def _trees() -> dict[str, ast.Module]:
    files = sorted(DEVPATH.glob("*.py"))
    return {p.name: ast.parse(p.read_text(encoding="utf-8")) for p in files}


def test_the_port_constant_is_defined_once() -> None:
    numbers: list[str] = []
    texts: list[str] = []
    built: list[str] = []
    for name, tree in _trees().items():
        docstrings = {
            id(node.value)
            for node in ast.walk(tree)
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and id(node) not in docstrings:
                if node.value == 3000:
                    numbers.append(name)
                if isinstance(node.value, str) and "3000" in node.value:
                    texts.append(name)
            if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "LabTarget":
                built.append(name)
    assert (numbers, texts, built) == (["targets.py"], [], ["targets.py"])


def test_no_environment_read_can_reach_the_target() -> None:
    for name, tree in _trees().items():
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert "os" not in {a.name.split(".")[0] for a in node.names}, name
            elif isinstance(node, ast.ImportFrom):
                assert (node.module or "").split(".")[0] != "os", name
            elif isinstance(node, ast.Attribute):
                assert node.attr not in ("environ", "getenv"), name
    tree = _trees()["targets.py"]
    imported = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    assert imported <= {"__future__", "typing"}
    assert not [n for n in ast.walk(tree) if isinstance(n, ast.Import)]


async def test_environment_variables_do_not_change_the_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in ("PORT", "JUICE_SHOP_PORT", "VULNSCOPE_JUICE_SHOP_PORT", "VULNSCOPE_TARGET"):
        monkeypatch.setenv(name, "5432")
    harness = Harness()
    harness.view_changes["status"] = "revoked"
    with no_network(monkeypatch):
        decision, _ = await harness.head(targets.JUICE_SHOP)
    assert decision.action.target == JUICE_URL
