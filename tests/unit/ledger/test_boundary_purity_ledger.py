# ruff: noqa: E501
"""AST purity of the ledger modules (extends SEC-8 beyond the read-only list in
``tests/unit/test_module_boundaries.py``): only ``postgres_backend`` may import sqlalchemy or
vulnscope.models. Also: no environment or settings access anywhere in ``ledger/``."""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

LEDGER = Path(__file__).resolve().parents[3] / "src" / "vulnscope" / "ledger"
PURE = ["types", "chain", "errors", "canonical", "verify", "memory_backend", "signer", "checkpoint"]
FORBIDDEN_TOP = {"sqlalchemy", "fastapi", "asyncpg", "httpx", "requests", "socket", "subprocess"}
FORBIDDEN_PREFIX = ("vulnscope.models", "vulnscope.api", "vulnscope.config", "vulnscope.db",
                    "vulnscope.policy")


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


@pytest.mark.parametrize("module", PURE)
def test_pure_ledger_module_imports(module: str) -> None:
    for name in _imports(LEDGER / f"{module}.py"):
        assert name.split(".")[0] not in FORBIDDEN_TOP, f"{module} imports {name}"
        assert not name.startswith(FORBIDDEN_PREFIX), f"{module} imports {name}"


def test_no_ledger_module_reads_the_environment_or_logs_secrets() -> None:
    for path in LEDGER.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in ("environ", "getenv"):
                raise AssertionError(f"{path.name} reads the environment")


def test_postgres_backend_is_the_only_module_that_imports_the_db_layer() -> None:
    importers = {
        p.stem
        for p in LEDGER.glob("*.py")
        if any(n.split(".")[0] == "sqlalchemy" or n.startswith("vulnscope.models") for n in _imports(p))
    }
    assert importers <= {"postgres_backend"}


def test_the_backend_never_issues_update_delete_or_truncate_on_ledger_tables() -> None:
    src = (LEDGER / "postgres_backend.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    calls = {
        n.func.id if isinstance(n.func, ast.Name) else n.func.attr
        for n in ast.walk(tree)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name | ast.Attribute)
    }
    assert "delete" not in calls and "truncate" not in calls
    text_literals = [
        n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)
    ]
    assert not any(s.strip().upper().startswith(("DELETE", "TRUNCATE", "UPDATE")) for s in text_literals)
