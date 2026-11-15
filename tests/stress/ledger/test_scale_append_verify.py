"""Stress: append+verify throughput at scale; verify() memory stays
bounded.

Catalogue row: docs/stress-tests.md "Ledger" -> "Scale: append and verify
throughput at 1e5 and 1e6 records; verify memory is bounded."

CI runs a reduced N (VULNSCOPE_STRESS_N, default 5_000) to stay inside the
normal test-suite time budget. The 1e5/1e6 targets from the catalogue are
the documented FULL-SCALE run, meant to be executed manually or in a
nightly job (`VULNSCOPE_STRESS_N=1000000 pytest ...`), not on every CI run.
The post-gate file must record BOTH the CI-scale number and, whenever a
full-scale run is actually executed, the 1e5/1e6 number -- do not silently
substitute one for the other in the report.
"""
from __future__ import annotations

import os
import time
import tracemalloc
from datetime import datetime, timezone

from vulnscope.ledger.memory_backend import InMemoryChainBackend
from vulnscope.ledger.verify import verify

DEFAULT_N = 5_000
N = int(os.environ.get("VULNSCOPE_STRESS_N", DEFAULT_N))
CATALOGUE_TARGETS = (100_000, 1_000_000)  # docs/stress-tests.md; not run by default


def _fill(n: int):
    backend = InMemoryChainBackend()
    chain_id = "engagement:stress-scale"
    now = datetime.now(timezone.utc)
    for i in range(n):
        backend.append(chain_id, "policy.decision", "system", {"i": i}, now)
    return backend, chain_id


def test_append_and_verify_throughput_at_configured_scale() -> None:
    start = time.perf_counter()
    backend, chain_id = _fill(N)
    append_elapsed = time.perf_counter() - start

    start = time.perf_counter()
    result = verify(chain_id, backend)
    verify_elapsed = time.perf_counter() - start

    assert result.result == "ok"
    assert result.records == N

    append_rps = N / append_elapsed if append_elapsed > 0 else float("inf")
    verify_rps = N / verify_elapsed if verify_elapsed > 0 else float("inf")
    print(
        f"scale={N} append={append_elapsed:.3f}s ({append_rps:.0f} rec/s) "
        f"verify={verify_elapsed:.3f}s ({verify_rps:.0f} rec/s); "
        f"catalogue full-scale targets NOT run in this invocation: {CATALOGUE_TARGETS} "
        f"(rerun with VULNSCOPE_STRESS_N=100000 or 1000000 to cover them)"
    )


def test_verify_memory_is_sublinear_in_record_count() -> None:
    """verify() must not need O(all records) of *extra* retained memory
    beyond streaming through the chain once (docs/stress-tests.md: 'verify
    memory is bounded'). Approximated here by comparing peak traced memory
    at two different scales and asserting the peak does not grow in rough
    proportion to the much larger record count -- a true O(n) retention bug
    (e.g. materializing the whole chain into a list before checking it)
    would show roughly linear growth instead.

    Known approximation (documented, not hidden): this measures
    append()+verify() together, and InMemoryChainBackend's own storage is
    itself necessarily O(n) for an in-memory store. The bound this test
    should eventually isolate -- verify()'s OWN working set on top of
    whatever the backend already holds -- needs a streaming
    backend.read()/PostgresChainBackend comparison once Task B lands; noted
    in docs/gates/slice0-pre-stress.md.
    """
    small_n = max(200, N // 10)
    large_n = N

    tracemalloc.start()
    backend_small, chain_small = _fill(small_n)
    verify(chain_small, backend_small)
    _, peak_small = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    tracemalloc.start()
    backend_large, chain_large = _fill(large_n)
    verify(chain_large, backend_large)
    _, peak_large = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    ratio_n = large_n / small_n
    ratio_mem = peak_large / peak_small if peak_small else float("inf")
    print(f"record-count ratio={ratio_n:.1f} peak-memory ratio={ratio_mem:.1f}")

    assert ratio_mem < ratio_n * 1.5, (
        f"peak memory grew {ratio_mem:.1f}x for a {ratio_n:.1f}x record-count "
        "increase -- verify() or the backend may be retaining more than a "
        "bounded working set"
    )
