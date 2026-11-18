# ruff: noqa: E501
"""Compare a real Phase R (or Phase G) JUnit report with tests/stress/db/expected_red.txt. R1.

Usage:  python -I tests/stress/db/check_phase_r.py <junit.xml> [--phase R|G] [expected_red.txt]

Phase R: for every expected row, the testcase must exist and (RED) fail/error with a message that
matches the row's regex, or (GREEN, GREEN-for-wrong-reason) pass; rows whose reason starts with
``MISSING:`` must be ABSENT from the report (implementer tests not written yet). Testcases that
are in the report but in neither expected_red.txt nor the inventory are reported as UNLISTED.
Phase G: every listed row must pass (no skips, no failures); nothing may be skipped.
Exit status 1 on any mismatch. Prints one line per mismatch and a summary; never prints secrets
(it only reads the report).
"""
from __future__ import annotations

import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

HERE = Path(__file__).resolve().parent


def nodeid(tc: ET.Element) -> str:
    cls = tc.get("classname") or ""
    return f"{cls.replace('.', '/')}.py::{tc.get('name')}"


def load_expected(path: Path) -> list[tuple[str, str, str]]:
    rows = []
    for ln in path.read_text(encoding="utf-8").splitlines():
        if ln.strip() and not ln.lstrip().startswith("#"):
            a, b, c = (p.strip() for p in ln.split(" | ", 2))
            rows.append((a, b, c))
    return rows


def main(argv: list[str]) -> int:
    args = [a for a in argv if not a.startswith("--")]
    phase = "G" if "--phase" in argv and argv[argv.index("--phase") + 1] == "G" else "R"
    args = [a for a in args if a not in ("R", "G")]
    junit = Path(args[0])
    expected_path = Path(args[1]) if len(args) > 1 else HERE / "expected_red.txt"
    cases: dict[str, tuple[str, str]] = {}
    for tc in ET.parse(junit).getroot().iter("testcase"):
        outcome, text = "passed", ""
        for ch in tc:
            if ch.tag in ("failure", "error", "skipped"):
                outcome = {"failure": "failed", "error": "error", "skipped": "skipped"}[ch.tag]
                text = (ch.get("message") or "") + "\n" + (ch.text or "")
        cases[nodeid(tc)] = (outcome, text)

    bad: list[str] = []
    listed = set()
    counts = {"RED": 0, "GREEN": 0, "GREEN-for-wrong-reason": 0}
    for node, outcome, reason in load_expected(expected_path):
        listed.add(node)
        got = cases.get(node)
        if phase == "G":
            if got is None:
                bad.append(f"ABSENT in Phase G: {node}")
            elif got[0] != "passed":
                bad.append(f"NOT GREEN in Phase G ({got[0]}): {node}")
            continue
        counts[outcome] += 1
        if reason.startswith("MISSING:"):
            if got is not None:
                bad.append(f"EXPECTED ABSENT but present ({got[0]}): {node}")
            continue
        if got is None:
            bad.append(f"ABSENT from report: {node}")
        elif outcome == "RED":
            if got[0] not in ("failed", "error"):
                bad.append(f"EXPECTED RED but {got[0]}: {node}")
            elif not re.search(reason, got[1], re.DOTALL):
                bad.append(f"RED FOR THE WRONG REASON: {node}\n    expected /{reason}/\n    got: {got[1][:300]!r}")
        elif got[0] != "passed":
            bad.append(f"EXPECTED {outcome} (passed) but {got[0]}: {node}\n    got: {got[1][:300]!r}")
    unlisted = sorted(set(cases) - listed)
    skipped = sorted(n for n, (o, _) in cases.items() if o == "skipped")
    for n in skipped:
        bad.append(f"SKIPPED (zero-skip rule): {n}")
    for n in unlisted:
        print(f"note: UNLISTED testcase (not in expected_red.txt): {n} -> {cases[n][0]}")
    for line in bad:
        print("MISMATCH:", line)
    print(
        f"SUMMARY phase={phase} report_cases={len(cases)} listed={len(listed)} unlisted={len(unlisted)} "
        f"expected={counts} mismatches={len(bad)}"
    )
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
