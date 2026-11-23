"""Token-bucket rate limiting with a per-engagement key quota (SEC-A8, RC7).

State lives in the instance, never at module level (D5). Keys look like
``<engagement_id>:<canonical host>``; engagement ids cannot contain ``:`` so the
engagement is everything before the first colon (a key without one is its own
engagement). The ceiling is per target host, not per engagement, so a wildcard
scope fans out across many buckets; that is bounded here per engagement so a
hostile or noisy engagement can only exhaust its own quota.
"""

from __future__ import annotations

import math
import threading
from dataclasses import dataclass
from typing import Protocol


class RateLimitStore(Protocol):
    def allow(self, key: str, limit_rps: float, now_monotonic: float) -> bool: ...


@dataclass
class _Bucket:
    tokens: float
    last: float
    rps: float
    capacity: float

    def refilled_at(self, now: float) -> float:
        elapsed = max(0.0, now - self.last)
        return min(self.capacity, self.tokens + elapsed * self.rps)


_MIN_FAIR_SHARE = 8
_GLOBAL_SWEEP_INTERVAL_S = 1.0


class InMemoryRateLimitStore:
    def __init__(self, max_keys: int = 100_000, max_keys_per_engagement: int = 2_000) -> None:
        if max_keys < 1 or max_keys_per_engagement < 1:
            raise ValueError("key caps must be positive")
        self._max_keys = max_keys
        self._max_per_engagement = max_keys_per_engagement
        self._lock = threading.Lock()
        self._buckets: dict[str, dict[str, _Bucket]] = {}
        self._total = 0
        self._last_global_sweep: float | None = None

    # -- introspection (tests and metrics) ---------------------------------------------
    def key_count(self) -> int:
        with self._lock:
            return self._total

    def engagement_key_count(self, engagement: str) -> int:
        with self._lock:
            return len(self._buckets.get(engagement, ()))

    # -- internals; callers hold the lock ----------------------------------------------
    def _sweep_engagement(self, engagement: str, now: float) -> None:
        keys = self._buckets.get(engagement)
        if not keys:
            return
        stale = [k for k, b in keys.items() if b.refilled_at(now) >= b.capacity]
        for k in stale:
            del keys[k]
        self._total -= len(stale)
        if not keys:
            del self._buckets[engagement]

    def _sweep_all(self, now: float) -> None:
        for engagement in list(self._buckets):
            self._sweep_engagement(engagement, now)
        self._last_global_sweep = now

    def _admit_new_key(self, engagement: str, now: float) -> bool:
        if len(self._buckets.get(engagement, ())) >= self._max_per_engagement:
            self._sweep_engagement(engagement, now)
            if len(self._buckets.get(engagement, ())) >= self._max_per_engagement:
                return False
        if self._total >= self._max_keys:
            last = self._last_global_sweep
            if last is None or now - last >= _GLOBAL_SWEEP_INTERVAL_S or now < last:
                self._sweep_all(now)
            if self._total >= self._max_keys:
                present = len(self._buckets) + (0 if engagement in self._buckets else 1)
                fair = max(_MIN_FAIR_SHARE, self._max_keys // present)
                if len(self._buckets.get(engagement, ())) >= fair:
                    return False
        return True

    def allow(self, key: str, limit_rps: float, now_monotonic: float) -> bool:
        if not (math.isfinite(limit_rps) and limit_rps > 0 and math.isfinite(now_monotonic)):
            return False
        engagement = key.split(":", 1)[0]
        capacity = max(1.0, limit_rps)
        with self._lock:
            keys = self._buckets.get(engagement)
            bucket = keys.get(key) if keys is not None else None
            if bucket is None:
                if not self._admit_new_key(engagement, now_monotonic):
                    return False
                bucket = _Bucket(
                    tokens=capacity, last=now_monotonic, rps=limit_rps, capacity=capacity
                )
                self._buckets.setdefault(engagement, {})[key] = bucket
                self._total += 1
            else:
                elapsed = max(0.0, now_monotonic - bucket.last)
                bucket.tokens = min(capacity, bucket.tokens + elapsed * limit_rps)
                bucket.rps = limit_rps
                bucket.capacity = capacity
                bucket.last = max(bucket.last, now_monotonic)
            if bucket.tokens >= 1.0:
                bucket.tokens -= 1.0
                return True
            return False
