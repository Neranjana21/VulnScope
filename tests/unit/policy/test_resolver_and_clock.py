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
