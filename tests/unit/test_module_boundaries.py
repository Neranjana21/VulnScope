"""Module-boundary purity check (pre-gate finding SEC-8, explicitly
required by the owner to land in Task 0).

docs/gates/slice0-plan.md Section 2's module-boundary rule: ``policy/``'s
and ``ledger/``'s pure logic (``types.py``, ``canonical.py``, ``decide.py``,
``verify.py``, ``target.py``, ``denylist.py``) must never import
``sqlalchemy``, ``fastapi``, or anything from ``models``/``api`` -- those
boundaries are bridged only through ``postgres_backend.py`` and
``api/policy_integration.py``.

Most of these files are Task A's (``policy/``) or Task B's (``ledger/``
backends) work, not built yet this task; only ``ledger/types.py`` and
``ledger/chain.py`` exist after Task 0 (moved here per SEC-4). Each path is
checked individually and skipped (not failed) if the file does not exist
yet, so this test keeps working unmodified once Task A/B land their files
-- it does not need to be re-authored at that point, only re-run.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

SRC_ROOT = Path(__file__).resolve().parents[1] / "src" / "vulnscope"

# Verbatim list from docs/gates/slice0-plan.md Section 2's module-boundary
# rule (paths relative to src/vulnscope/).
PURE_MODULE_RELATIVE_PATHS = [
    "policy/types.py",
    "policy/decide.py",
    "policy/target.py",
    "policy/denylist.py",
    "ledger/types.py",
    "ledger/canonical.py",
    "ledger/verify.py",
]

# ledger/chain.py is not named in the plan's Section 2 list verbatim, but
# it was moved into Task 0 for the same purity reason (fixes SEC-4,
# Section 3.1.1) and must hold the same rule -- checked as an addition,
# not a substitution, below.
ADDITIONAL_PURE_MODULE_RELATIVE_PATHS = ["ledger/chain.py"]

FORBIDDEN_TOP_LEVEL_MODULES = {"sqlalchemy", "fastapi"}
FORBIDDEN_DOTTED_PREFIXES = ("vulnscope.models", "vulnscope.api")


def _imported_module_names(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


def _assert_no_forbidden_import(relative_path: str) -> None:
    file_path = SRC_ROOT / relative_path
    if not file_path.exists():
        pytest.skip(f"{relative_path} does not exist yet (built in a later task)")
    tree = ast.parse(file_path.read_text(encoding="utf-8"), filename=str(file_path))
    for module_name in _imported_module_names(tree):
        top_level = module_name.split(".")[0]
        assert top_level not in FORBIDDEN_TOP_LEVEL_MODULES, (
            f"{relative_path} imports forbidden module {module_name!r} "
            "(policy/ and ledger/'s pure modules must not import sqlalchemy/fastapi)"
        )
        for forbidden_prefix in FORBIDDEN_DOTTED_PREFIXES:
            assert not module_name.startswith(forbidden_prefix), (
                f"{relative_path} imports forbidden module {module_name!r} "
                "(policy/ and ledger/'s pure modules must not import models/ or api/)"
            )


@pytest.mark.parametrize("relative_path", PURE_MODULE_RELATIVE_PATHS)
def test_pure_module_has_no_forbidden_import(relative_path: str) -> None:
    _assert_no_forbidden_import(relative_path)


@pytest.mark.parametrize("relative_path", ADDITIONAL_PURE_MODULE_RELATIVE_PATHS)
def test_additional_pure_module_has_no_forbidden_import(relative_path: str) -> None:
    _assert_no_forbidden_import(relative_path)
