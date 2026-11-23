"""One entry point (rule 1): `decide` has exactly one reference in production code.

Design 11.1 RC4. The reference lives in policy/decide_and_record.py as args[0] of
``asyncio.to_thread``. Documented limit: dynamic importlib/getattr is not detected.
"""

from __future__ import annotations

import ast
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src" / "vulnscope"


def _references(source: str) -> dict[str, list]:
    tree = ast.parse(source)
    parents: dict[ast.AST, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent
    imports, refs = [], []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == "decide":
                    imports.append((node.module, alias.asname))
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.endswith("policy.decide"):
                    imports.append((alias.name, alias.asname))
        elif isinstance(node, ast.Name) and node.id == "decide":
            refs.append((node, parents.get(node)))
        elif isinstance(node, ast.Attribute) and node.attr == "decide":
            refs.append((node, parents.get(node)))
    return {"imports": imports, "refs": refs}


def _is_to_thread_first_arg(node: ast.AST, parent: ast.AST | None) -> bool:
    if not isinstance(parent, ast.Call) or not parent.args or parent.args[0] is not node:
        return False
    fn = parent.func
    return (
        isinstance(fn, ast.Attribute)
        and fn.attr == "to_thread"
        and isinstance(fn.value, ast.Name)
        and fn.value.id == "asyncio"
    )


def test_exactly_one_import_and_one_reference() -> None:
    importers, ref_total = [], []
    for path in sorted(SRC.rglob("*.py")):
        found = _references(path.read_text(encoding="utf-8"))
        rel = path.relative_to(SRC).as_posix()
        importers += [(rel, i) for i in found["imports"]]
        for node, parent in found["refs"]:
            ref_total.append((rel, _is_to_thread_first_arg(node, parent)))
    assert [(r, i[0]) for r, i in importers] == [
        ("policy/decide_and_record.py", "vulnscope.policy.decide")
    ]
    assert importers[0][1][1] is None, "no alias for decide"
    assert ref_total == [("policy/decide_and_record.py", True)]


def test_policy_init_does_not_export_decide() -> None:
    tree = ast.parse((SRC / "policy" / "__init__.py").read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            assert all(a.name != "decide" for a in node.names)
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            assert node.value != "decide"


def test_checker_flags_extra_references() -> None:
    bad = [
        "from vulnscope.policy.decide import decide\nx = decide",
        "from vulnscope.policy.decide import decide as d",
        "import asyncio\nfrom vulnscope.policy.decide import decide\n"
        "asyncio.to_thread(decide)\ny = decide",
        "import vulnscope.policy.decide\nvulnscope.policy.decide.decide(1)",
        "def f(cb=decide): ...",
    ]
    for src in bad:
        found = _references(src)
        total = len(found["refs"]) + len(found["imports"])
        ok = (
            len(found["imports"]) == 1
            and len(found["refs"]) == 1
            and found["imports"][0][1] is None
            and _is_to_thread_first_arg(*found["refs"][0])
        )
        assert not ok and total >= 1, src
    good = (
        "import asyncio\nfrom vulnscope.policy.decide import decide\n"
        "async def f():\n    return await asyncio.to_thread(decide, 1)"
    )
    found = _references(good)
    assert len(found["imports"]) == 1 and len(found["refs"]) == 1
    assert _is_to_thread_first_arg(*found["refs"][0])
