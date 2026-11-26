"""Repository guard: no bidi controls or invisible format characters in tracked code.

Such characters (Unicode category ``Cf``) can make source read differently from how it
runs. The typed escape TEXT (backslash, ``u``, four hex digits) is plain ASCII and is not
counted; write that instead of the character itself.

Seven files that predate this guard are pinned to their exact counts. The list may only
shrink: more characters, fewer characters, or a new file all fail. Every tracked file
under the scanned directories must be UTF-8; nothing is skipped.
"""

from __future__ import annotations

import subprocess
import unicodedata
from collections.abc import Iterable, Mapping
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCANNED = ("src", "devpath", "tests")
PINNED: Mapping[str, int] = {
    "src/vulnscope/policy/target.py": 2,
    "tests/fixtures/target_corpus/target_corpus.py": 2,
    "tests/integration/ledger/test_postgres_hostile_payloads.py": 2,
    "tests/property/policy/test_target_parser.py": 4,
    "tests/stress/ledger/test_hostile_payload_denial.py": 2,
    "tests/unit/policy/test_decide_deny_cases.py": 1,
    "tests/unit/policy/test_engagement_check.py": 1,
}


def scan(root: Path, names: Iterable[str]) -> tuple[dict[str, int], list[str]]:
    """``(count of Cf characters per file that has any, files that are not UTF-8)``."""
    counts: dict[str, int] = {}
    undecodable: list[str] = []
    for name in names:
        try:
            text = (root / name).read_bytes().decode("utf-8")
        except UnicodeDecodeError:
            undecodable.append(name)
            continue
        except FileNotFoundError:
            continue  # a pinned file that is gone is reported as having fewer characters
        found = sum(1 for char in text if unicodedata.category(char) == "Cf")
        if found:
            counts[name] = found
    return counts, undecodable


def violations(
    counts: Mapping[str, int], undecodable: Iterable[str], pinned: Mapping[str, int]
) -> list[str]:
    problems = [f"{name}: not UTF-8, so it cannot be checked" for name in sorted(undecodable)]
    for name in sorted(set(counts) | set(pinned)):
        found, allowed = counts.get(name, 0), pinned.get(name, 0)
        if found > allowed:
            problems.append(
                f"{name}: {found} invisible or bidi characters, {allowed} allowed; "
                "type them as \\uXXXX escapes"
            )
        elif found < allowed:
            problems.append(
                f"{name}: {found} invisible or bidi characters, pinned at {allowed}; "
                "the list may only shrink, so lower or remove this pin deliberately"
            )
    return problems


def tracked_files() -> list[str]:
    listing = subprocess.run(
        ["git", "ls-files", "-z", "--", *SCANNED],
        cwd=ROOT,
        capture_output=True,
        check=True,
        timeout=60,
    ).stdout
    return [raw.decode("utf-8") for raw in listing.split(b"\0") if raw]


def test_tracked_files_have_no_unpinned_invisible_characters() -> None:
    names = tracked_files()
    assert {name.split("/")[0] for name in names} == set(SCANNED)
    assert violations(*scan(ROOT, names), PINNED) == []


def test_the_pin_list_is_the_seven_older_files_only() -> None:
    assert len(PINNED) == 7
    assert "tests/unit/report/test_report_render.py" not in PINNED


@pytest.mark.parametrize(
    "name", ["tests/unit/test_invisible_characters.py", "tests/unit/report/test_report_render.py"]
)
def test_this_guard_and_the_report_tests_are_clean(name: str) -> None:
    assert (ROOT / name).is_file()
    assert scan(ROOT, [name]) == ({}, [])


@pytest.mark.parametrize("codepoint", [0x00AD, 0x200B, 0x202E, 0x2063, 0x2066, 0xFEFF])
def test_a_planted_character_in_a_new_file_fails(tmp_path: Path, codepoint: int) -> None:
    (tmp_path / "new.py").write_bytes(f"x = '{chr(codepoint)}'\n".encode())
    problems = violations(*scan(tmp_path, ["new.py"]), {})
    assert len(problems) == 1 and problems[0].startswith("new.py: 1 ")


def test_typed_escape_text_is_not_counted(tmp_path: Path) -> None:
    (tmp_path / "typed.py").write_bytes(b"x = '\\u202e\\u2063'\n")
    assert scan(tmp_path, ["typed.py"]) == ({}, [])


@pytest.mark.parametrize(
    ("found", "message"),
    [(3, "2 allowed"), (1, "may only shrink"), (0, "may only shrink")],
    ids=["one-extra", "one-fewer", "all-gone"],
)
def test_a_pinned_file_must_match_exactly(found: int, message: str) -> None:
    counts = {"old.py": found} if found else {}
    [problem] = violations(counts, [], {"old.py": 2})
    assert message in problem
    assert violations({"old.py": 2}, [], {"old.py": 2}) == []


def test_a_non_utf8_file_fails_instead_of_being_skipped(tmp_path: Path) -> None:
    (tmp_path / "latin1.py").write_bytes(b"x = '\xff'\n")
    counts, undecodable = scan(tmp_path, ["latin1.py"])
    assert (counts, undecodable) == ({}, ["latin1.py"])
    assert violations(counts, undecodable, {}) == ["latin1.py: not UTF-8, so it cannot be checked"]
