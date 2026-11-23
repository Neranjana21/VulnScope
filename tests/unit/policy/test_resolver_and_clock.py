"""SystemResolver (socket patched; no real DNS) and SystemClock."""

from __future__ import annotations

import socket
import time
from datetime import timedelta

import pytest

from vulnscope.policy import resolver as resolver_mod
from vulnscope.policy.clock import SystemClock
from vulnscope.policy.resolver import ResolutionError, SystemResolver


def _info(*addrs: str) -> list[tuple]:
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, 0)) for a in addrs]


def test_returns_textual_ips_dedup_and_strips_zone(monkeypatch: pytest.MonkeyPatch) -> None:
    infos = _info("192.0.2.1", "192.0.2.1", "192.0.2.2")
    infos.append((socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("fe80::1%eth0", 0, 0, 2)))
    monkeypatch.setattr(resolver_mod.socket, "getaddrinfo", lambda *a, **k: infos)
    r = SystemResolver()
    try:
        assert r.resolve("x.test") == ("192.0.2.1", "192.0.2.2", "fe80::1")
    finally:
        r.close()


def test_failure_modes_raise_resolution_error(monkeypatch: pytest.MonkeyPatch) -> None:
    r = SystemResolver()
    try:

        def boom(*a: object, **k: object) -> list:
            raise socket.gaierror(-2, "Name or service not known")

        monkeypatch.setattr(resolver_mod.socket, "getaddrinfo", boom)
        with pytest.raises(ResolutionError):
            r.resolve("x.test")
        monkeypatch.setattr(resolver_mod.socket, "getaddrinfo", lambda *a, **k: [])
        with pytest.raises(ResolutionError):
            r.resolve("x.test")
    finally:
        r.close()


def test_timeout_raises_and_does_not_hang(monkeypatch: pytest.MonkeyPatch) -> None:
    def slow(*a: object, **k: object) -> list:
        time.sleep(0.5)
        return _info("192.0.2.1")

    monkeypatch.setattr(resolver_mod.socket, "getaddrinfo", slow)
    r = SystemResolver(timeout_s=0.05)
    try:
        start = time.perf_counter()
        with pytest.raises(ResolutionError):
            r.resolve("x.test")
        assert time.perf_counter() - start < 0.4
    finally:
        r.close()


def test_result_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    many = _info(*[f"192.0.2.{i}" for i in range(1, 60)])
    monkeypatch.setattr(resolver_mod.socket, "getaddrinfo", lambda *a, **k: many)
    r = SystemResolver(max_results=32)
    try:
        # the pin set must be complete: too many answers fail closed, never truncate
        with pytest.raises(ResolutionError):
            r.resolve("x.test")
    finally:
        r.close()


def test_system_clock() -> None:
    c = SystemClock()
    assert c.now().utcoffset() == timedelta(0)
    a = c.monotonic()
    assert c.monotonic() >= a


def _try(r: SystemResolver, host: str = "x.test") -> object:
    try:
        return r.resolve(host)
    except ResolutionError:
        return "failed"


def test_bounded_in_flight_fails_closed_when_full(monkeypatch: pytest.MonkeyPatch) -> None:
    import threading

    release = threading.Event()
    started = threading.Semaphore(0)

    def blocked(*a: object, **k: object) -> list:
        started.release()
        release.wait(5)
        return _info("192.0.2.1")

    monkeypatch.setattr(resolver_mod.socket, "getaddrinfo", blocked)
    r = SystemResolver(timeout_s=5, max_inflight=2)
    results: list[object] = []
    threads = [threading.Thread(target=lambda: results.append(_try(r))) for _ in range(2)]
    try:
        for t in threads:
            t.start()
        started.acquire()
        started.acquire()
        begin = time.perf_counter()
        with pytest.raises(ResolutionError):
            r.resolve("third.test")  # both slots held: fails closed immediately
        assert time.perf_counter() - begin < 0.5
    finally:
        release.set()
        for t in threads:
            t.join()
        r.close()
    assert results == [("192.0.2.1",), ("192.0.2.1",)]
    monkeypatch.setattr(resolver_mod.socket, "getaddrinfo", lambda *a, **k: _info("192.0.2.2"))
    r2 = SystemResolver(max_inflight=2)
    try:
        for _ in range(5):  # slots are released after completion
            assert r2.resolve("x.test") == ("192.0.2.2",)
    finally:
        r2.close()


def test_pending_futures_are_cancelled_on_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    import threading

    release = threading.Event()
    calls: list[str] = []

    def blocked(host: str, *a: object, **k: object) -> list:
        calls.append(host)
        release.wait(5)
        return _info("192.0.2.1")

    monkeypatch.setattr(resolver_mod.socket, "getaddrinfo", blocked)
    r = SystemResolver(timeout_s=0.15, max_inflight=8)
    outcomes: list[object] = []
    threads = [
        threading.Thread(target=lambda i=i: outcomes.append(_try(r, f"h{i}.test")))
        for i in range(7)
    ]
    try:
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert outcomes == ["failed"] * 7
        release.set()
        time.sleep(0.3)  # queued lookups would run now if they had not been cancelled
        assert len(calls) == 4
    finally:
        release.set()
        r.close()


def test_submit_failure_releases_the_slot_every_time(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(resolver_mod.socket, "getaddrinfo", lambda *a, **k: _info("192.0.2.1"))
    r = SystemResolver(max_inflight=2)
    r.close()  # every later submit raises
    for _ in range(10):
        with pytest.raises(ResolutionError, match="unavailable"):
            r.resolve("x.test")  # a leaked slot would turn this into "busy" after 2 calls


def test_default_bound_is_eight_and_the_ninth_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import threading

    release = threading.Event()
    monkeypatch.setattr(
        resolver_mod.socket, "getaddrinfo", lambda *a, **k: (release.wait(5), _info("192.0.2.1"))[1]
    )
    r = SystemResolver(timeout_s=5)
    threads = [threading.Thread(target=_try, args=(r, f"h{i}.test")) for i in range(8)]
    try:
        for t in threads:
            t.start()
        deadline = time.perf_counter() + 2
        while r._slots._value != 0 and time.perf_counter() < deadline:  # noqa: SLF001
            time.sleep(0.01)
        with pytest.raises(ResolutionError, match="busy"):
            r.resolve("ninth.test")
    finally:
        release.set()
        for t in threads:
            t.join()
        r.close()
