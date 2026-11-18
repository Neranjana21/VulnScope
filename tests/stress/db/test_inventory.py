# ruff: noqa: E501
"""Stress #12 (GR-STR-4, GR-STR-22): committed inventory, expected_red.txt coverage, zero-skip. R1.

* every inventory node exists (implementer tests that do not exist yet are reported here: red in
  Phase R, green after the fix);
* no collected integration node is missing from the inventory (a deleted/unlisted test fails);
* expected_red.txt covers every collected tests/stress/db node and nothing stale;
* the zero-skip hook is proved on a synthetic test in a temp dir (subprocess), including the
  inventory-enforcement session hook.
No database needed.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
import vulnscope_db_plugin as kit

EXPECTED_RED = kit.HERE / "expected_red.txt"
OUTCOMES = {"RED", "GREEN", "GREEN-for-wrong-reason"}


def _expected_rows() -> list[tuple[str, str, str]]:
    rows = []
    for ln in EXPECTED_RED.read_text(encoding="utf-8").splitlines():
        if not ln.strip() or ln.lstrip().startswith("#"):
            continue
        parts = [p.strip() for p in ln.split(" | ", 2)]
        assert len(parts) == 3, f"malformed expected_red line: {ln!r}"
        rows.append((parts[0], parts[1], parts[2]))
    return rows


def test_inventory_file_is_well_formed_and_duplicate_free() -> None:
    inv = kit.load_inventory()
    assert inv, "inventory is empty"
    assert len(inv) == len(set(inv)), "duplicate inventory lines"
    bad = [ln for ln in inv if not re.match(r"^tests/[\w/.-]+\.py::\S", ln)]
    assert not bad, f"malformed inventory lines: {bad[:3]}"


def test_every_inventory_node_is_collected() -> None:
    nodes = kit.collect_nodes(["tests/integration", "tests/stress/db"], integration_only=True)
    missing = [e for e in kit.load_inventory() if not kit.inventory_matches(e, nodes)]
    assert not missing, (
        f"MISSING: {len(missing)} inventory node(s) not collected (implementer tests not written, "
        f"or marker/file deleted): " + "; ".join(missing)
    )


def test_no_collected_integration_node_is_missing_from_the_inventory() -> None:
    nodes = kit.collect_nodes(["tests/integration", "tests/stress/db"], integration_only=True)
    inv = kit.load_inventory()
    unlisted = sorted(n for n in nodes if not any(kit.inventory_matches(e, {n}) for e in inv))
    assert not unlisted, f"UNLISTED integration nodes ({len(unlisted)}): " + "; ".join(unlisted[:10])


def test_expected_red_file_is_well_formed() -> None:
    rows = _expected_rows()
    seen = set()
    for node, outcome, reason in rows:
        assert outcome in OUTCOMES, f"{node}: outcome {outcome!r} not in {sorted(OUTCOMES)}"
        re.compile(reason)  # must be a valid regex
        assert node not in seen, f"duplicate expected_red node {node}"
        seen.add(node)
        if outcome != "GREEN":
            assert reason.strip(), f"{node}: a non-GREEN outcome needs a reason"


def test_expected_red_covers_every_collected_node_and_nothing_stale() -> None:
    """Phase R runs tests/stress/db, tests/integration and tests/unit/{db,infra}: every collected node
    needs a row, and no row may be stale (MISSING: rows are for nodes that must be absent)."""
    collected = kit.collect_nodes(
        ["tests/stress/db", "tests/integration", "tests/unit/db", "tests/unit/infra"],
        integration_only=False,
    )
    rows = _expected_rows()
    listed = {n for n, _, reason in rows if not reason.startswith("MISSING:")}
    assert collected, "collect-only returned nothing"
    assert not collected - listed, f"nodes missing from expected_red.txt: {sorted(collected - listed)[:8]}"
    assert not listed - collected, f"stale expected_red.txt entries: {sorted(listed - collected)[:8]}"


# ------------------------------------------------------------------ the zero-skip hook, end to end
SKIPPER = """
import pytest

@pytest.mark.integration
def test_skips_for_a_missing_env():
    pytest.skip("VULNSCOPE_X not set")

@pytest.mark.integration
def test_passes():
    assert True

def test_unmarked_skip_outside_stress_db_is_untouched():
    pytest.skip("unit-style skip")
"""


def _run_child(tmp: Path, env_extra: dict[str, str]) -> subprocess.CompletedProcess[str]:
    (tmp / "pytest.ini").write_text("[pytest]\nmarkers =\n    integration: x\n", encoding="utf-8")
    (tmp / "test_child.py").write_text(SKIPPER, encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if not k.startswith("VULNSCOPE_")}
    env.update({"PYTHONPATH": str(kit.HERE), **env_extra})
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-p", "vulnscope_db_plugin", "-p", "no:cacheprovider",
         "--strict-markers", "-rs", "-q", str(tmp / "test_child.py")],
        cwd=tmp, env=env, capture_output=True, text=True, timeout=120,
    )


def test_without_require_a_missing_env_skip_is_reported_as_a_skip(tmp_path: Path) -> None:
    p = _run_child(tmp_path, {})
    assert p.returncode == 0, p.stdout + p.stderr
    assert "2 skipped" in p.stdout and "1 passed" in p.stdout, p.stdout


def test_with_require_every_integration_skip_becomes_a_failure(tmp_path: Path) -> None:
    p = _run_child(tmp_path, {"VULNSCOPE_REQUIRE_INTEGRATION": "1"})
    assert p.returncode != 0, "a skipped integration test must fail the run under REQUIRE"
    assert "SKIP FORBIDDEN" in p.stdout + p.stderr, p.stdout
    assert "1 failed" in p.stdout and "1 passed" in p.stdout, p.stdout
    assert "1 skipped" in p.stdout, "the non-integration skip must stay a skip: " + p.stdout


def test_inventory_enforce_fails_the_session_when_inventory_nodes_did_not_run(tmp_path: Path) -> None:
    p = _run_child(
        tmp_path,
        {"VULNSCOPE_REQUIRE_INTEGRATION": "1", "VULNSCOPE_INVENTORY_ENFORCE": "1"},
    )
    assert p.returncode != 0
    assert "INVENTORY ENFORCE" in p.stderr + p.stdout, p.stdout + p.stderr


@pytest.mark.parametrize("flag", ["0", "", "true", "yes"])
def test_only_the_exact_value_1_turns_on_require(monkeypatch: pytest.MonkeyPatch, flag: str) -> None:
    monkeypatch.setenv("VULNSCOPE_REQUIRE_INTEGRATION", flag)
    assert kit.require_integration() is False
    monkeypatch.setenv("VULNSCOPE_REQUIRE_INTEGRATION", "1")
    assert kit.require_integration() is True
