"""Test doubles for the API (D-early). They live only under tests/ (PD-23) and open no socket.

Protocol-level fakes for the ports in ``vulnscope.api.ports``: an in-memory chain backend with fault
injection, a clock, a creation-time target checker (exact match, tiny deny list), a scan gate that
emulates the policy lifecycle rules and appends a ``policy.decision`` entry for every decision
(rule 8), verify and checkpoint doubles, and a sanitizer with the same shape as the real one.
"""
from __future__ import annotations

import asyncio
import ipaddress
from collections.abc import AsyncIterator, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

from vulnscope.api.ports import EngagementSnapshot, GateVerdict, TargetFinding
from vulnscope.ledger.types import Checkpoint, LedgerEntry, VerifyResult

ALWAYS_DENY_HOSTS = {"169.254.169.254", "metadata.google.internal"}
ALWAYS_DENY_NETS = [ipaddress.ip_network("169.254.0.0/16")]
_BLOCKED_KEYS = {"authorization", "cookie", "set-cookie", "proxy-authorization", "password",
                 "secret", "token"}


class FakeClock:
    def __init__(self, now: datetime | None = None) -> None:
        self._now = now or datetime.now(UTC)
        self._mono = 1000.0

    def now(self) -> datetime:
        return self._now

    def monotonic(self) -> float:
        return self._mono

    def advance(self, **kw: float) -> None:
        self._now += timedelta(**kw)
        self._mono += timedelta(**kw).total_seconds()


class RealClock:
    def now(self) -> datetime:
        return datetime.now(UTC)

    def monotonic(self) -> float:
        import time

        return time.monotonic()


def sanitize(payload: Mapping[str, object]) -> dict[str, object]:
    def walk(v: Any) -> Any:
        if isinstance(v, dict):
            return {k: ("[redacted]" if str(k).lower() in _BLOCKED_KEYS else walk(x))
                    for k, x in v.items()}
        if isinstance(v, list):
            return [walk(x) for x in v]
        if isinstance(v, float):
            return "[float]"
        return v

    out = walk(dict(payload))
    assert isinstance(out, dict)
    return out


class BackendFailure(RuntimeError):
    pass


class MemoryChain:
    """ChainBackend double: per-chain lists, fake hashes, fault injection, call counters."""

    def __init__(self) -> None:
        self.chains: dict[str, list[LedgerEntry]] = {}
        self.fail_next_appends = 0
        self.fail_always = False
        self.calls: list[tuple[str, str]] = []  # (method, chain_id)
        self.read_delay = 0.0
        self.append_delay = 0.0

    def count(self, method: str | None = None) -> int:
        return len([c for c in self.calls if method is None or c[0] == method])

    def entries(self, chain_id: str, kind: str | None = None) -> list[LedgerEntry]:
        return [e for e in self.chains.get(chain_id, []) if kind is None or e.kind == kind]

    def prefill(self, chain_id: str, n: int, kind: str = "filler") -> None:
        for i in range(n):
            self._put(chain_id, kind, "system", {"i": i}, datetime.now(UTC))

    def _put(self, chain_id: str, kind: str, actor: str, payload: Mapping[str, object],
             ts: datetime) -> LedgerEntry:
        lst = self.chains.setdefault(chain_id, [])
        seq = len(lst)
        prev = lst[-1].record_hash if lst else "0" * 64
        e = LedgerEntry(1, chain_id, seq, kind, actor, dict(payload), ts, prev,
                        f"{abs(hash((chain_id, seq, kind))):064x}"[-64:])
        lst.append(e)
        return e

    async def append(self, chain_id: str, kind: str, actor: str,
                     payload: Mapping[str, object], ts: datetime) -> LedgerEntry:
        self.calls.append(("append", chain_id))
        if self.append_delay:
            await asyncio.sleep(self.append_delay)
        if self.fail_always:
            raise BackendFailure("canary-should-never-surface")
        if self.fail_next_appends > 0:
            self.fail_next_appends -= 1
            raise BackendFailure("canary-should-never-surface")
        return self._put(chain_id, kind, actor, payload, ts)

    async def read(self, chain_id: str, start_seq: int = 0,
                   limit: int | None = None) -> AsyncIterator[LedgerEntry]:
        self.calls.append(("read", chain_id))
        items = list(self.chains.get(chain_id, []))[start_seq:]
        if limit is not None:
            items = items[:limit]
        for i, e in enumerate(items):
            if self.read_delay:
                await asyncio.sleep(self.read_delay)
            if i % 256 == 0:
                await asyncio.sleep(0)
            yield e

    async def head(self, chain_id: str) -> LedgerEntry | None:
        self.calls.append(("head", chain_id))
        lst = self.chains.get(chain_id, [])
        return lst[-1] if lst else None

    async def record_count(self, chain_id: str) -> int:
        self.calls.append(("record_count", chain_id))
        return len(self.chains.get(chain_id, []))


class FakeVerify:
    def __init__(self, result: VerifyResult | None = None) -> None:
        self.result = result
        self.calls: list[str] = []
        self.hang = False
        self.delay = 0.0

    async def __call__(self, chain_id: str, backend: Any,
                       checkpoint: Checkpoint | None = None) -> VerifyResult:
        self.calls.append(chain_id)
        if self.hang:
            await asyncio.Event().wait()
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.result is not None:
            return self.result
        n = await backend.record_count(chain_id)
        return VerifyResult("ok", None, n, checkpoint.seq if checkpoint else None)


class FakeCheckpointSource:
    def __init__(self, checkpoint: Checkpoint | None = None) -> None:
        self.checkpoint = checkpoint

    async def latest_valid(self, chain_id: str) -> Checkpoint | None:
        return self.checkpoint


class FakeTargetChecker:
    """Exact-match coverage, tiny always-deny list, range overlap with 169.254/16, 0.0.0.0/0."""

    def check(self, *, domains: Sequence[str], ip_ranges: Sequence[str], openapi_url: str | None,
              allow: Sequence[str], deny: Sequence[str], expected: Sequence[str], profile: str,
              lab_enabled: bool, lab_cidr: str | None) -> list[TargetFinding]:
        denied: list[TargetFinding] = []
        outside: list[TargetFinding] = []
        items: list[tuple[int, str, str]] = [(i, "domain", d) for i, d in enumerate(domains)]
        items += [(i, "range", r) for i, r in enumerate(ip_ranges)]
        if openapi_url:
            items.append((0, "openapi", openapi_url.split("//", 1)[-1].split("/")[0]))
        for idx, kind, t in items:
            if t.lower() in ALWAYS_DENY_HOSTS or t in deny:
                denied.append(TargetFinding(idx, kind, "TARGET_DENIED", "always_deny_or_deny"))
                continue
            if kind == "range":
                net = ipaddress.ip_network(t, strict=False)
                if any(net.overlaps(n) for n in ALWAYS_DENY_NETS) or net.prefixlen == 0:
                    denied.append(TargetFinding(idx, kind, "TARGET_DENIED", "range_overlap"))
                    continue
            if t not in allow:
                outside.append(TargetFinding(idx, kind, "TARGET_NOT_IN_SCOPE", "not_covered"))
        return denied + outside


class FakeScanGate:
    """Emulates the policy lifecycle rules; every decision is appended to the engagement chain."""

    def __init__(self, chain: MemoryChain, clock: Any, settings_enable_lab: bool = True) -> None:
        self.chain = chain
        self.clock = clock
        self.canned: dict[str, str] = {}  # target -> deny rule_id
        self.calls: list[dict[str, str]] = []
        self.exc: Exception | None = None
        self.hang = False
        self.block: Any = None  # threading.Event for thread-blocking resolver emulation
        self.delay = 0.0
        self.inflight = 0
        self.max_inflight = 0
        self.lab_enabled = settings_enable_lab

    def rule_for(self, e: EngagementSnapshot, target: str) -> str | None:
        win = e.scope["window"]
        nb = datetime.fromisoformat(str(win["not_before"]).replace("Z", "+00:00"))
        na = datetime.fromisoformat(str(win["not_after"]).replace("Z", "+00:00"))
        now = self.clock.now()
        if e.status == "revoked":
            return "REVOKED"
        if now >= na:
            return "EXPIRED"
        if now < nb:
            return "NOT_YET_VALID"
        if e.profile == "lab" and not self.lab_enabled:
            return "OUT_OF_SCOPE"
        if target in e.scope.get("deny", []):
            return "EXCLUDED"
        if target in self.canned:
            return self.canned[target]
        if target in ALWAYS_DENY_HOSTS:
            return "DENY_ALWAYS_LIST"
        return None

    async def check(self, *, engagement: EngagementSnapshot, target: str, adapter: str,
                    actor: str) -> GateVerdict:
        self.calls.append({"target": target, "adapter": adapter, "actor": actor})
        self.inflight += 1
        self.max_inflight = max(self.max_inflight, self.inflight)
        try:
            if self.exc is not None:
                raise self.exc
            if self.hang:
                await asyncio.Event().wait()
            if self.block is not None:
                await asyncio.to_thread(self.block.wait, 2.0)
            if self.delay:
                await asyncio.sleep(self.delay)
            rule = self.rule_for(engagement, target)
            allowed = rule is None
            e = await self.chain.append(
                f"engagement:{engagement.id}", "policy.decision", actor,
                {"schema_version": 1, "allowed": allowed, "rule_id": rule or "ALLOW",
                 "adapter": adapter}, self.clock.now())
            return GateVerdict(allowed, rule or "ALLOW", e.seq)
        finally:
            self.inflight -= 1
