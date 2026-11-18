# ruff: noqa: E501
"""GR-STR-20 mechanical guard: no module-level import of not-yet-existing modules. R1.

If any test or conftest under tests/stress/db or tests/integration imports
vulnscope.db.migration_grants / vulnscope.db.role_checks / static_checks at module level (even
inside a top-level ``if``/``try``/``with``), pytest aborts the whole session at collection and
Phase R cannot produce a per-test red list. This test fails loudly instead, naming the file and
line. ``pytest.importorskip`` is banned for the same reason (it would turn red into skip).
The guard itself is verified against synthetic sources.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest
import vulnscope_db_plugin as kit

FORBIDDEN = {"vulnscope.db.migration_grants", "vulnscope.db.role_checks", "static_checks"}
FORBIDDEN_NAMES_FROM_DB = {"migration_grants", "role_checks"}
SCANNED = [kit.REPO_ROOT / "tests" / "stress" / "db", kit.REPO_ROOT / "tests" / "integration"]


def _visit(nodes: list[ast.stmt], out: list[str]) -> None:
    for n in nodes:
        if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef):
            continue  # imports inside function bodies are the required pattern
        if isinstance(n, ast.Import):
            out += [f"line {n.lineno}: import {a.name}" for a in n.names if a.name in FORBIDDEN]
        elif isinstance(n, ast.ImportFrom):
            mod = n.module or ""
            if mod in FORBIDDEN or (
                mod == "vulnscope.db" and any(a.name in FORBIDDEN_NAMES_FROM_DB for a in n.names)
            ):
                out.append(f"line {n.lineno}: from {mod} import {', '.join(a.name for a in n.names)}")
        for field in ("body", "orelse", "finalbody", "handlers"):
            child = getattr(n, field, None)
            if isinstance(child, list):
                _visit([c for c in child if isinstance(c, ast.stmt)] + [
                    s for c in child if isinstance(c, ast.ExceptHandler) for s in c.body
                ], out)


def top_level_forbidden_imports(source: str) -> list[str]:
    out: list[str] = []
    _visit(ast.parse(source).body, out)
    return out


def importorskip_calls(source: str) -> list[str]:
    return [
        f"line {n.lineno}"
        for n in ast.walk(ast.parse(source))
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "importorskip"
    ]


@pytest.mark.parametrize(
    ("src", "flagged"),
    [
        ("import vulnscope.db.migration_grants\n", True),
        ("from vulnscope.db import migration_grants as mg\n", True),
        ("from vulnscope.db.role_checks import role_violations\n", True),
        ("try:\n    import static_checks\nexcept ImportError:\n    pass\n", True),
        ("if True:\n    from vulnscope.db import role_checks\n", True),
        ("def f():\n    import vulnscope.db.migration_grants\n", False),
        ("import importlib\nx = lambda: importlib.import_module('vulnscope.db.migration_grants')\n", False),
        ("from vulnscope.db.session import get_async_engine\n", False),
    ],
)
def test_the_guard_itself_flags_what_it_should(src: str, flagged: bool) -> None:
    assert bool(top_level_forbidden_imports(src)) is flagged


def _files() -> list[Path]:
    return sorted(p for root in SCANNED for p in root.rglob("*.py") if "__pycache__" not in p.parts)


def test_no_module_level_import_of_not_yet_existing_modules() -> None:
    offenders = []
    for path in _files():
        for hit in top_level_forbidden_imports(path.read_text(encoding="utf-8")):
            offenders.append(f"{path.relative_to(kit.REPO_ROOT)}: {hit}")
    assert not offenders, (
        "GR-STR-20 violated (a top-level import turns Phase R into one collection error): "
        + "; ".join(offenders)
    )


def test_importorskip_is_not_used_in_the_scanned_trees() -> None:
    offenders = []
    for path in _files():
        if path.name == Path(__file__).name:
            continue
        for hit in importorskip_calls(path.read_text(encoding="utf-8")):
            offenders.append(f"{path.relative_to(kit.REPO_ROOT)}: {hit}")
    assert not offenders, "importorskip turns red into skip: " + "; ".join(offenders)
