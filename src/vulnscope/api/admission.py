"""Admission control: bounded concurrency for the expensive paths (PD-08, PD-10, PD-15, N-03,
N-06). Pure asyncio, no I/O. A flood degrades to fast 503s, never to hangs.
"""
from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass

from vulnscope.api.limits import Timeouts
from vulnscope.api.problem import Detail, ProblemError
from vulnscope.errors import ReasonCode


def _unavailable(retry_after: int = 1) -> ProblemError:
    return ProblemError(503, ReasonCode.UNAVAILABLE, Detail.UNAVAILABLE,
                        headers={"Retry-After": str(retry_after)})


class AuthGate:
    """Bounds concurrent API-key lookups. ``reserved`` slots are usable only by the revoke route
    (the protective act), so a flood on other routes cannot block revocation."""

    def __init__(self, shared: int, reserved: int, wait_s: float) -> None:
        self._shared = asyncio.Semaphore(shared)
        self._reserved = asyncio.Semaphore(reserved)
        self._wait_s = wait_s

    @staticmethod
    async def _try(sem: asyncio.Semaphore) -> bool:
        if sem.locked():
            return False
        await sem.acquire()  # not locked: completes without suspending
        return True

    @asynccontextmanager
    async def slot(self, *, reserved_ok: bool) -> AsyncIterator[None]:
        held: asyncio.Semaphore
        if await self._try(self._shared):
            held = self._shared
        elif reserved_ok and await self._try(self._reserved):
            held = self._reserved
        else:
            try:
                async with asyncio.timeout(self._wait_s):
                    await self._shared.acquire()
                held = self._shared
            except TimeoutError:
                raise _unavailable() from None
        try:
            yield
        finally:
            held.release()


class OrgPermit:
    """A scan-creation slot. ``release_later`` keeps the slot for a grace period (N-06): after a
    deadline the resolver thread may still be blocked, so the slot is not freed immediately."""

    def __init__(self, gate: OrgGate, org_id: str) -> None:
        self._gate = gate
        self._org_id = org_id
        self._released = False

    def release(self) -> None:
        if not self._released:
            self._released = True
            self._gate._release(self._org_id)

    def release_later(self, delay_s: float) -> None:
        asyncio.get_running_loop().call_later(delay_s, self.release)


class _OrgEntry:
    def __init__(self, n: int) -> None:
        self.sem = asyncio.Semaphore(n)
        self.refs = 0


class OrgGate:
    """Per-org semaphore map (idle entries removed, so org-id spray cannot grow it) plus a global
    semaphore."""

    def __init__(self, per_org: int, global_n: int, wait_s: float) -> None:
        self._per_org = per_org
        self._global = asyncio.Semaphore(global_n)
        self._wait_s = wait_s
        self._orgs: dict[str, _OrgEntry] = {}

    def active_orgs(self) -> int:
        return len(self._orgs)

    async def acquire(self, org_id: str) -> OrgPermit:
        entry = self._orgs.setdefault(org_id, _OrgEntry(self._per_org))
        entry.refs += 1
        got_org = False
        try:
            async with asyncio.timeout(self._wait_s):
                await entry.sem.acquire()
                got_org = True
                await self._global.acquire()
        except TimeoutError:
            if got_org:
                entry.sem.release()
            self._drop(org_id)
            raise _unavailable() from None
        except BaseException:
            if got_org:
                entry.sem.release()
            self._drop(org_id)
            raise
        return OrgPermit(self, org_id)

    def _drop(self, org_id: str) -> None:
        entry = self._orgs.get(org_id)
        if entry is not None:
            entry.refs -= 1
            if entry.refs <= 0:
                del self._orgs[org_id]

    def _release(self, org_id: str) -> None:
        entry = self._orgs.get(org_id)
        self._global.release()
        if entry is not None:
            entry.sem.release()
            self._drop(org_id)


class VerifyPermit:
    def __init__(self, gate: VerifyGate, org_id: str) -> None:
        self._gate, self._org_id, self._released = gate, org_id, False

    def release(self) -> None:
        if not self._released:
            self._released = True
            self._gate._release(self._org_id)


class VerifyGate:
    """No queue: a caller that cannot enter immediately gets 503 (global cap and one per org)."""

    def __init__(self, global_n: int) -> None:
        self._global_n = global_n
        self._used = 0
        self._orgs: set[str] = set()

    def try_acquire(self, org_id: str) -> VerifyPermit:
        if self._used >= self._global_n or org_id in self._orgs:
            raise _unavailable(2)
        self._used += 1
        self._orgs.add(org_id)
        return VerifyPermit(self, org_id)

    def _release(self, org_id: str) -> None:
        self._used -= 1
        self._orgs.discard(org_id)


@dataclass(frozen=True)
class Gates:
    auth: AuthGate
    org: OrgGate
    verify: VerifyGate


def build_gates(t: Timeouts) -> Gates:
    return Gates(
        auth=AuthGate(t.auth_inflight, t.auth_reserved, t.auth_queue_wait_s),
        org=OrgGate(t.scan_inflight_per_org, t.scan_inflight_global, t.admission_wait_s),
        verify=VerifyGate(t.verify_inflight_global),
    )
