"""Test-owned stand-in for the lab app, and the port 3000 safety net.

Nothing here talks to a real lab app. The audit hook blocks every connect to port 3000
unless this test process holds that port itself.
"""

from __future__ import annotations

import socket
import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import pytest

PORT = 3000  # deliberately independent of the code under test
OK = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
_OWNED = [False]


def _guard(event: str, args: tuple[Any, ...]) -> None:
    if event != "socket.connect" or _OWNED[0]:
        return
    address = args[1]
    if isinstance(address, tuple) and len(address) > 1 and address[1] == PORT:
        raise RuntimeError("test safety net: connect to port 3000 that this test does not own")


sys.addaudithook(_guard)


def _bind() -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Rebinding after TIME_WAIT only: on Linux it cannot take over a live listener.
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("127.0.0.1", PORT))
    except OSError:
        sock.close()
        pytest.fail(
            "127.0.0.1:3000 is in use by something this test did not start; "
            "stop it and run again. Nothing was sent.",
            pytrace=False,
        )
    return sock


@contextmanager
def silent_port() -> Iterator[None]:
    """We hold the port but do not listen, so a connect is really refused."""
    sock = _bind()
    _OWNED[0] = True
    try:
        yield
    finally:
        _OWNED[0] = False
        sock.close()


class FakeLabApp:
    """``response=None`` stalls: reads the request and never answers."""

    def __init__(self, response: bytes | None = OK) -> None:
        self.response = response
        self.requests: list[bytes] = []
        self.got_request = threading.Event()
        self.client_closed = threading.Event()
        self._sock = _bind()
        self._sock.listen(8)
        self._sock.settimeout(0.05)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        _OWNED[0] = True
        self._thread.start()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        with conn:
            try:
                conn.settimeout(10.0)
                data = b""
                while b"\r\n\r\n" not in data:
                    chunk = conn.recv(4096)
                    if not chunk:
                        return
                    data += chunk
                self.requests.append(data)
                self.got_request.set()
                if self.response is None:
                    while conn.recv(4096):
                        pass
                    self.client_closed.set()
                    return
                conn.sendall(self.response)
            except OSError:
                pass

    def close(self) -> None:
        _OWNED[0] = False
        self._stop.set()
        self._thread.join(2.0)
        self._sock.close()

    def __enter__(self) -> FakeLabApp:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
