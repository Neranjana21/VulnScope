# ruff: noqa: E501
"""Stress (R1): static isolation guard for Task B's own integration tests (design F13 / F14 guard 3,
finding C1). ``tests/integration/ledger/**`` must never reach the shared dev database or the
migrator role by environment variable, and must not use the shared-DB guard:

* banned: any string that contains ``DATABASE_URL`` other than the exact name
  ``VULNSCOPE_TEST_DATABASE_URL`` (covers VULNSCOPE_DATABASE_URL, VULNSCOPE_MIGRATION_DATABASE_URL,
  VULNSCOPE_TEST_APP_DATABASE_URL, including split or concatenated spellings, f-strings and
  fragments such as ``"DATABASE_URL"``), and the identifier ``require_safe_dev_database_url``;
* required: the directory exists with at least one test file (red until Task B writes them) and the
  fixtures assert ``current_database()`` against ``vulnscope_(stress|taskb)_`` before appending.

Pure static analysis (ast + text); nothing is imported or executed from the scanned files.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2] / "integration" / "ledger"
ALLOWED_ENV = "VULNSCOPE_TEST_DATABASE_URL"
BANNED_IDENT = "require_safe_dev_database_url"


def _docstring_nodes(tree: ast.AST) -> set[int]:
    ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                ids.add(id(body[0].value))
    return ids


def _fold(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _fold(node.left), _fold(node.right)
        return left + right if left is not None and right is not None else None
    if isinstance(node, ast.JoinedStr):
        return "".join(v.value if isinstance(v, ast.Constant) else "\x00" for v in node.values)
    return None


def banned_hits(source: str) -> list[str]:
    """Return fixed-text reasons (never source excerpts) for every violation in ``source``."""
    tree = ast.parse(source)
    skip = _docstring_nodes(tree)
    hits: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Name | ast.Attribute):
            ident = node.id if isinstance(node, ast.Name) else node.attr
            if ident == BANNED_IDENT:
                hits.append("banned identifier")
        elif isinstance(node, ast.alias):
            if BANNED_IDENT in (node.name, node.asname):
                hits.append("banned import")
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            if node.name == BANNED_IDENT:
                hits.append("banned definition")
        text = None
        if isinstance(node, ast.Constant | ast.BinOp | ast.JoinedStr) and id(node) not in skip:
            text = _fold(node)
        if text is not None and "DATABASE_URL" in text and text != ALLOWED_ENV:
            hits.append("banned database env name")
        if text is not None and BANNED_IDENT in text:
            hits.append("banned identifier in string")
    return hits


def _files() -> list[Path]:
    return sorted(ROOT.rglob("*.py")) if ROOT.is_dir() else []


# ------------------------------------------------------------------ the checker itself (green now)
@pytest.mark.parametrize("src", [
    'import os\nos.environ["VULNSCOPE_DATABASE_URL"]',
    'import os\nos.getenv("VULNSCOPE_MIGRATION_DATABASE_URL")',
    'x = "VULNSCOPE_TEST_APP_DATABASE_URL"',
    'x = "VULNSCOPE_" + "DATABASE_URL"',
    'x = "VULNSCOPE_MIGRATION_" "DATABASE_URL"',
    'y = "MIGRATION"\nx = f"VULNSCOPE_{y}_DATABASE_URL"',
    'x = "DATABASE_URL"',
    'from _guard import require_safe_dev_database_url',
    'import _guard\n_guard.require_safe_dev_database_url()',
    'from _guard import require_safe_dev_database_url as ok',
    'f = require_safe_dev_database_url',
    'def require_safe_dev_database_url(): pass',
])
def test_checker_catches_evasions(src: str) -> None:
    # Known gap (not tested, by design): the shared-guard identifier split across string pieces for
    # getattr(); the env-name bans and the import ban cover every realistic route to that helper.
    assert banned_hits(src), "violation not detected"


@pytest.mark.parametrize("src", [
    'import os\nos.environ.get("VULNSCOPE_TEST_DATABASE_URL")',
    '"""docstring mentioning VULNSCOPE_DATABASE_URL"""\nx = 1',
    'def f():\n    """uses require_safe_dev_database_url never"""\n    return 1',
    'x = "vulnscope_(stress|taskb)_"',
])
def test_checker_accepts_clean_sources(src: str) -> None:
    assert banned_hits(src) == []


# ------------------------------------------------------------------ the guard on the real directory
def test_ledger_integration_directory_exists_with_tests() -> None:
    assert ROOT.is_dir(), "tests/integration/ledger/ must exist (Task B integration tests)"
    names = {p.name for p in _files() if p.name.startswith("test_")}
    assert names, "tests/integration/ledger/ has no test files"


def test_no_shared_database_env_names_or_shared_guard_in_ledger_integration_tests() -> None:
    offenders = {p.name: sorted(set(banned_hits(p.read_text(encoding="utf-8")))) for p in _files()}
    offenders = {k: v for k, v in offenders.items() if v}
    assert not offenders, f"isolation violations (file -> reasons): {offenders}"


def test_integration_fixtures_assert_current_database_is_a_scratch_or_task_db() -> None:
    texts = [p.read_text(encoding="utf-8") for p in _files()]
    assert any("current_database" in t and "vulnscope_(stress|taskb)_" in t for t in texts), (
        "a ledger integration fixture must run SELECT current_database() and match "
        "vulnscope_(stress|taskb)_ before the first append (F14 guard 2)"
    )
