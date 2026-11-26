"""Compare a JUnit report with ``expected_red.txt`` (stdlib only; run with ``python -I``).

    python -I tests/acceptance/api/check_expected_red.py <report.xml> [expected_red.txt]

Exit 0 only when every node's outcome matches its inventory line, no inventory node is missing from
the report, and no reported node is absent from the inventory. A skipped test is always a
mismatch (zero-skip rule). Output is boolean per node; nothing from a failure message is printed.
"""
from __future__ import annotations

import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def load_inventory(path: Path) -> dict[str, tuple[str, str]]:
    out: dict[str, tuple[str, str]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        node, outcome, reason = (p.strip() for p in line.split("|", 2))
        out[node] = (outcome, reason)
    return out


def node_id(tc: ET.Element) -> str:
    cls = tc.get("classname", "")
    mod = cls.replace(".", "/") + ".py"
    return f"{mod}::{tc.get('name', '')}"


def main(argv: list[str]) -> int:
    report = Path(argv[1])
    inv_path = Path(argv[2]) if len(argv) > 2 else Path(__file__).with_name("expected_red.txt")
    inv = load_inventory(inv_path)
    seen: set[str] = set()
    bad = 0
    for tc in ET.parse(report).iter("testcase"):
        node = node_id(tc)
        seen.add(node)
        kinds = [c.tag for c in tc if c.tag in ("failure", "error", "skipped")]
        text = " ".join((c.get("message") or "") + (c.text or "") for c in tc
                        if c.tag in ("failure", "error"))
        actual = "GREEN" if not kinds else ("SKIPPED" if "skipped" in kinds else "RED")
        want = inv.get(node)
        ok = (want is not None and actual == want[0]
              and (actual != "RED" or re.search(want[1], text, re.DOTALL) is not None))
        if not ok:
            bad += 1
            print(f"MISMATCH {node}: actual={actual} inventoried={'no' if want is None else want[0]}")
    for node in inv:
        if node not in seen:
            bad += 1
            print(f"MISSING from report: {node}")
    print(f"nodes_reported={len(seen)} inventory={len(inv)} mismatches={bad}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
