"""SEC-A8 / RC7: per-engagement key quota; one tenant cannot starve another."""

from __future__ import annotations

import threading

from vulnscope.policy.ratelimit import InMemoryRateLimitStore


def test_engagement_quota_isolation() -> None:
    s = InMemoryRateLimitStore(max_keys=1000, max_keys_per_engagement=10)
    for i in range(10):
        assert s.allow(f"A:h{i}", 0.5, 0.0)
    assert not s.allow("A:new", 0.5, 0.0)  # RATE for A only
    assert s.allow("B:h0", 0.5, 0.0)  # B unaffected
    assert s.allow("A:h3", 0.5, 2.0)  # an existing key still refills
    assert s.engagement_key_count("A") == 10


def test_quota_sweeps_refilled_buckets_first() -> None:
    s = InMemoryRateLimitStore(max_keys=1000, max_keys_per_engagement=4)
    for i in range(4):
        assert s.allow(f"A:h{i}", 1.0, 0.0)
    assert not s.allow("A:x", 1.0, 0.1)
    assert s.allow("A:x", 1.0, 5.0)  # all four refilled and swept, x admitted
    assert s.engagement_key_count("A") <= 4


def test_key_without_colon_is_its_own_engagement() -> None:
    s = InMemoryRateLimitStore(max_keys=100, max_keys_per_engagement=2)
    assert s.allow("solo", 1.0, 0.0)
    assert s.allow("other", 1.0, 0.0)
    assert not s.allow("solo", 1.0, 0.0)


def test_ipv6_host_in_key_does_not_confuse_engagement_prefix() -> None:
    s = InMemoryRateLimitStore(max_keys=100, max_keys_per_engagement=1)
    assert s.allow("A:2001:db8::1", 0.1, 0.0)
    assert not s.allow("A:2001:db8::2", 0.1, 0.0)
    assert s.allow("B:2001:db8::1", 0.1, 0.0)


def test_global_cap_never_evicts_live_foreign_buckets() -> None:
    s = InMemoryRateLimitStore(max_keys=500, max_keys_per_engagement=10)
    engagements = [f"E{i}" for i in range(50)]
    for e in engagements:
        for k in range(10):
            assert s.allow(f"{e}:h{k}", 0.001, 0.0)
    assert s.key_count() == 500
    assert s.allow("NEW:h0", 0.001, 0.0)  # 51st engagement still admitted (fair share)
    for e in engagements:
        assert not s.allow(f"{e}:another", 0.001, 0.0)  # at quota
        assert s.engagement_key_count(e) == 10  # nothing evicted
    assert s.key_count() <= 500 + 8 * 51


def test_global_sweep_restores_admission_after_time_passes() -> None:
    s = InMemoryRateLimitStore(max_keys=20, max_keys_per_engagement=10)
    for e in ("A", "B"):
        for k in range(10):
            assert s.allow(f"{e}:h{k}", 1.0, 0.0)
    assert s.allow("C:h", 1.0, 0.0)  # fair share
    assert s.allow("C:h2", 1.0, 100.0)  # everything refilled, swept
    assert s.key_count() <= 20 + 8 * 3


def test_threaded_quota() -> None:
    s = InMemoryRateLimitStore(max_keys=1000, max_keys_per_engagement=20)
    admitted: list[bool] = []
    lock = threading.Lock()

    def worker(n: int) -> None:
        for i in range(30):
            r = s.allow(f"A:t{n}-{i}", 0.001, 0.0)
            with lock:
                admitted.append(r)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert admitted.count(True) == 20
    assert s.allow("B:x", 0.001, 0.0)
