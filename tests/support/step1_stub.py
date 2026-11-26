"""Our own throwaway HTTP stub for Step 1. Binds 127.0.0.1 on a random port, nothing else.

It is the ONLY thing the Step 1 development path may talk to (ADR-0013).
"""

from __future__ import annotations

import socket
import threading
from types import TracebackType
from typing import Literal

StubMode = Literal["insecure", "secure", "redirect", "stall"]

REDIRECT_LOCATION = "http://169.254.169.254/"
_SECURE_HEADERS = (
    b"Content-Security-Policy: default-src 'none'\r\n"
    b"X-Frame-Options: DENY\r\n"
    b"X-Content-Type-Options: nosniff\r\n"
    b"Referrer-Policy: no-referrer\r\n"
    b"Permissions-Policy: geolocation=()\r\n"
)
_TAIL = b"Content-Length: 0\r\nConnection: close\r\n\r\n"
_RESPONSES: dict[str, bytes] = {
    "insecure": b"HTTP/1.1 200 OK\r\n" + _TAIL,
    "secure": b"HTTP/1.1 200 OK\r\n" + _SECURE_HEADERS + _TAIL,
    "redirect": b"HTTP/1.1 302 Found\r\nLocation: " + REDIRECT_LOCATION.encode() + b"\r\n" + _TAIL,
}


class RunningStub:
    """``raw_response`` replaces the canned bytes, for hostile-response tests."""

    def __init__(self, mode: StubMode = "insecure", *, raw_response: bytes | None = None) -> None:
        if mode not in ("insecure", "secure", "redirect", "stall"):
            raise ValueError("unknown stub mode")
        self.mode: StubMode = mode
        self._raw = raw_response
        self._lock = threading.Condition()
        self._requests: list[bytes] = []
        self._client_closed = 0
        self._open: list[socket.socket] = []
        self._peers: list[object] = []
        self._stopping = False
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(16)
        self._port: int = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    @property
    def port(self) -> int:
        """The bound port of the RUNNING stub; raises once the stub is closed."""
        if self._stopping:
            raise RuntimeError("stub is not running")
        return self._port

    @property
    def request_count(self) -> int:
        with self._lock:
            return len(self._requests)

    @property
    def requests(self) -> tuple[bytes, ...]:
        with self._lock:
            return tuple(self._requests)

    def wait_for_requests(self, n: int, timeout_s: float = 2.0) -> bool:
        with self._lock:
            return self._lock.wait_for(lambda: len(self._requests) >= n, timeout_s)

    def wait_for_client_close(self, timeout_s: float = 2.0) -> bool:
        with self._lock:
            return self._lock.wait_for(lambda: self._client_closed >= 1, timeout_s)

    def connections_before_now(self) -> int:
        """Number of connections made so far. Race free: a sentinel connection is made and
        awaited, and the listen queue is FIFO, so every earlier one is already counted."""
        with socket.create_connection(("127.0.0.1", self._port), timeout=2.0) as probe:
            mine = probe.getsockname()
            with self._lock:
                if not self._lock.wait_for(lambda: mine in self._peers, 2.0):
                    raise RuntimeError("stub did not accept the sentinel connection")
                return self._peers.index(mine)

    def close(self) -> None:
        if self._stopping:
            return
        self._stopping = True
        try:
            socket.create_connection(("127.0.0.1", self._port), timeout=1.0).close()  # wake accept
        except OSError:
            pass
        self._thread.join(2.0)
        self._sock.close()
        with self._lock:
            for conn in self._open:
                conn.close()

    def __enter__(self) -> RunningStub:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def _serve(self) -> None:
        while True:
            try:
                conn, peer = self._sock.accept()
            except OSError:
                return
            if self._stopping:
                conn.close()
                return
            with self._lock:
                self._peers.append(peer)
                self._open.append(conn)
                self._lock.notify_all()
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(10.0)
            data = b""
            while b"\r\n\r\n" not in data and len(data) < 65536:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                data += chunk
            with self._lock:
                self._requests.append(data)
                self._lock.notify_all()
            if self.mode == "stall" and self._raw is None:
                while conn.recv(4096):
                    pass
                with self._lock:
                    self._client_closed += 1
                    self._lock.notify_all()
                return
            conn.sendall(self._raw if self._raw is not None else _RESPONSES[self.mode])
        except OSError:
            pass
        finally:
            conn.close()
