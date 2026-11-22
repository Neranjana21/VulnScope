"""Token bucket behaviour on a fake monotonic clock (STR-A2 item 3)."""

from __future__ import annotations

import math
import threading

import pytest

from vulnscope.policy.ratelimit import InMemoryRateLimitStore, RateLimitStore


def test_no_arg_constructor_and_protocol() -> None:
    store: RateLimitStore = InMemoryRateLimitStore()
    assert store.allow("e:h", 1.0, 0.0)


def test_capacity_one_at_one_rps() -> None:
    s = InMemoryRateLimitStore()
    assert s.allow("e:h", 1.0, 0.0)
    assert not s.allow("e:h", 1.0, 0.0)
    assert not s.allow("e:h", 1.0, 0.5)
    assert s.allow("e:h", 1.0, 1.0)


def test_capacity_equals_rps_for_large_rps() -> None:
    s = InMemoryRateLimitStore()
    assert all(s.allow("e:h", 1000.0, 0.0) for _ in range(1000))
    assert not s.allow("e:h", 1000.0, 0.0)
    assert s.allow("e:h", 1000.0, 0.002)


def test_fractional_rps_has_capacity_one() -> None:
    s = InMemoryRateLimitStore()
    assert s.allow("e:h", 0.25, 0.0)
    assert not s.allow("e:h", 0.25, 3.9)
    assert s.allow("e:h", 0.25, 4.0)


def test_refill_never_exceeds_capacity() -> None:
    s = InMemoryRateLimitStore()
    for _ in range(3):
        s.allow("e:h", 3.0, 0.0)
    assert [s.allow("e:h", 3.0, 100.0) for _ in range(5)] == [True, True, True, False, False]


def test_non_monotonic_input_never_refills() -> None:
    s = InMemoryRateLimitStore()
    assert s.allow("e:h", 1.0, 10.0)
    assert not s.allow("e:h", 1.0, 5.0)
    assert not s.allow("e:h", 1.0, 10.5)
    assert s.allow("e:h", 1.0, 11.0)


@pytest.mark.parametrize("rps", [math.nan, math.inf, -math.inf, 0.0, -1.0])
def test_bad_rps_denies(rps: float) -> None:
    assert not InMemoryRateLimitStore().allow("e:h", rps, 0.0)


@pytest.mark.parametrize("now", [math.nan, math.inf])
def test_bad_clock_denies(now: float) -> None:
    assert not InMemoryRateLimitStore().allow("e:h", 1.0, now)


def test_keys_are_independent() -> None:
    s = InMemoryRateLimitStore()
    assert s.allow("e:a", 1.0, 0.0) and s.allow("e:b", 1.0, 0.0) and s.allow("f:a", 1.0, 0.0)
    assert not s.allow("e:a", 1.0, 0.0)


def test_threads_never_exceed_capacity() -> None:
    s = InMemoryRateLimitStore()
    results: list[bool] = []
    lock = threading.Lock()

    def worker() -> None:
        for _ in range(50):
            r = s.allow("e:h", 100.0, 0.0)
            with lock:
                results.append(r)

    threads = [threading.Thread(target=worker) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(True) == 100
    assert len(results) == 800
