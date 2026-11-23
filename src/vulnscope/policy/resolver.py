"""Injected resolver. The ONLY ``policy/`` module allowed to do network I/O.

``decide`` reaches ``resolve`` at most once per call and only after the target
passed every pure check (steps 0-4b), so an unauthorised name never triggers a
lookup. There is no cache: the returned tuple is the PIN SET for that decision.
"""

from __future__ import annotations

import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from typing import Protocol


class ResolutionError(Exception):
    """NXDOMAIN, timeout, empty or oversized answer. ``decide`` records RESOLUTION_FAILED."""


class Resolver(Protocol):
    def resolve(self, hostname: str) -> tuple[str, ...]: ...


class SystemResolver:
    """``getaddrinfo`` in an instance-owned executor with a hard timeout.

    Residual (documented): a ``getaddrinfo`` call that is already RUNNING cannot be
    interrupted; it keeps its worker thread and its in-flight slot until it returns.
    Queued lookups are cancelled on timeout, and the in-flight bound makes the resolver
    fail closed instead of queueing without limit.
    """

    def __init__(
        self, timeout_s: float = 3.0, max_results: int = 32, max_inflight: int = 8
    ) -> None:
        if not timeout_s > 0:
            raise ValueError("timeout_s must be positive")
        if max_results < 1:
            raise ValueError("max_results must be >= 1")
        if max_inflight < 1:
            raise ValueError("max_inflight must be >= 1")
        # Bounded in-flight lookups (running + queued). When full, resolve() fails closed
        # at once, so tarpitted names cannot starve every engagement (T11).
        self._slots = threading.BoundedSemaphore(max_inflight)
        self._timeout_s = timeout_s
        self._max_results = max_results
        self._pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="vulnscope-resolver")

    def resolve(self, hostname: str) -> tuple[str, ...]:
        if not self._slots.acquire(blocking=False):
            raise ResolutionError("resolver busy")
        try:
            future = self._pool.submit(socket.getaddrinfo, hostname, None, 0, socket.SOCK_STREAM)
        except BaseException as exc:
            self._slots.release()
            raise ResolutionError("resolver unavailable") from exc
        # The slot is held until the lookup really finishes (or is cancelled before starting).
        future.add_done_callback(lambda _f: self._slots.release())
        try:
            infos = future.result(timeout=self._timeout_s)
        except FutureTimeout as exc:
            future.cancel()  # a still-queued lookup never starts
            raise ResolutionError("resolution timed out") from exc
        except (OSError, RuntimeError, UnicodeError) as exc:
            raise ResolutionError("resolution failed") from exc
        seen: dict[str, None] = {}
        for info in infos:
            address = str(info[4][0]).split("%", 1)[0]
            seen.setdefault(address, None)
        if not seen:
            raise ResolutionError("no addresses")
        if len(seen) > self._max_results:
            raise ResolutionError("too many addresses")
        return tuple(seen)

    def close(self) -> None:
        """Shutdown path: do not wait for hung lookups."""
        self._pool.shutdown(wait=False, cancel_futures=True)
