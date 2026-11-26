"""The sender accepts only the real stub type, and takes the port from its listening socket.

Every look-alike must be refused before a view is read, a decision is made or a socket
exists.
"""

from __future__ import annotations

import socket
from collections.abc import Iterator
from typing import Any

import pytest
from devpath import transport
from devpath.stub import RunningStub
from test_devpath_transport import Harness


@pytest.fixture
def real() -> Iterator[RunningStub]:
    with RunningStub("insecure") as running:
        yield running


@pytest.fixture
def sockets(monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    seen: list[Any] = []
    make = transport._new_socket

    def spy() -> Any:
        seen.append(make())
        return seen[-1]

    monkeypatch.setattr(transport, "_new_socket", spy)
    return seen


async def _assert_refused(stub: Any, code: str, sockets: list[Any]) -> None:
    harness = Harness()
    with pytest.raises(transport.SendRefused) as caught:
        await harness.head(stub)
    assert caught.value.code == code
    assert (harness.events, harness.ledger.entries, sockets) == ([], [], [])


async def test_duck_typed_stub_is_refused(sockets: list[Any]) -> None:
    class Duck:
        port = 5432

    await _assert_refused(Duck(), "not_the_real_stub", sockets)


async def test_class_spoofing_stub_is_refused(sockets: list[Any]) -> None:
    class Liar:
        port = 5432

        @property
        def __class__(self) -> type:  # fools isinstance, not type()
            return RunningStub

    assert isinstance(Liar(), RunningStub)
    await _assert_refused(Liar(), "not_the_real_stub", sockets)


async def test_subclass_reporting_another_port_is_refused(sockets: list[Any]) -> None:
    class Sub(RunningStub):
        @property
        def port(self) -> int:
            return 5432

    with Sub("insecure") as sub:
        await _assert_refused(sub, "not_the_real_stub", sockets)
        assert sub.connections_before_now() == 0


def test_port_cannot_be_assigned(real: RunningStub) -> None:
    with pytest.raises(AttributeError):
        real.port = 5432  # type: ignore[misc]


async def test_port_comes_from_the_socket_not_from_any_attribute(
    real: RunningStub, monkeypatch: pytest.MonkeyPatch
) -> None:
    bound = real.port
    real._port = 5432  # type: ignore[attr-defined]
    real.__dict__["port"] = 5432
    monkeypatch.setattr(RunningStub, "port", property(lambda self: 5432))
    decision, response = await Harness().head(real)
    assert response is not None
    assert decision.action.target == f"http://127.0.0.1:{bound}/"
    assert real.request_count == 1


async def test_fake_socket_object_is_refused(real: RunningStub, sockets: list[Any]) -> None:
    class FakeSocket:
        family = socket.AF_INET

        def getsockname(self) -> tuple[str, int]:
            return ("127.0.0.1", 5432)

    original = real._sock
    real._sock = FakeSocket()  # type: ignore[assignment]
    try:
        await _assert_refused(real, "not_the_real_stub", sockets)
    finally:
        real._sock = original


@pytest.mark.parametrize("listening", [False, True], ids=["not-listening", "not-loopback-pin"])
async def test_swapped_socket_must_be_a_listener_on_the_pinned_address(
    real: RunningStub, sockets: list[Any], listening: bool
) -> None:
    original = real._sock
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as other:
        # 127.0.0.2 is loopback too, but not the pinned address.
        other.bind(("127.0.0.2" if listening else "127.0.0.1", 0))
        if listening:
            other.listen(1)
        real._sock = other
        try:
            await _assert_refused(real, "not_the_real_stub", sockets)
        finally:
            real._sock = original


async def test_uninitialised_instance_is_refused(sockets: list[Any]) -> None:
    await _assert_refused(object.__new__(RunningStub), "not_the_real_stub", sockets)
