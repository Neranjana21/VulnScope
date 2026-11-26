"""Structural guards over src/vulnscope/api (design 12.1, PD-01, PD-09, PD-14, PD-23)."""
from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[3] / "src" / "vulnscope"
API = SRC / "api"
ROUTERS = API / "routers"
MODEL_MODS = {"vulnscope.models.engagement", "vulnscope.models.scan",
              "vulnscope.models.idempotency", "vulnscope.models.api_key"}
MODEL_IMPORTERS = {"scoping.py", "idempotency.py", "auth.py", "revoke_recorder.py",
                   "scan_status.py", "wiring.py"}


def api_files() -> list[Path]:
    files = sorted(API.rglob("*.py"))
    assert files, "src/vulnscope/api does not exist"
    return files


def imports(path: Path) -> set[str]:
    out: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            out |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            out.add(node.module)
            out |= {f"{node.module}.{a.name}" for a in node.names}
    return out


def test_no_policy_module_imported_in_d_early() -> None:
    for p in api_files():
        bad = {m for m in imports(p) if m.startswith("vulnscope.policy")}
        assert not bad, f"{p.name} imports {sorted(bad)}"


def test_only_pure_ledger_modules_imported() -> None:
    allowed = {"vulnscope.ledger", "vulnscope.ledger.chain", "vulnscope.ledger.types",
               "vulnscope.ledger.types.LedgerEntry", "vulnscope.ledger.types.Checkpoint",
               "vulnscope.ledger.types.VerifyResult", "vulnscope.ledger.chain.ChainBackend"}
    for p in api_files():
        bad = {m for m in imports(p) if m.startswith("vulnscope.ledger")} - allowed
        assert not bad or p.name == "wiring.py", f"{p.name} imports {sorted(bad)}"


def test_routers_never_import_the_four_model_modules() -> None:
    for p in sorted(ROUTERS.glob("*.py")):
        bad = {m for m in imports(p) if m in MODEL_MODS or m.startswith("vulnscope.models.api_key")}
        assert not bad, f"{p.name} imports {sorted(bad)}"


def test_only_allowed_modules_import_the_four_model_modules() -> None:
    for p in api_files():
        hit = {m for m in imports(p) if any(m == x or m.startswith(x + ".") for x in MODEL_MODS)}
        if hit:
            assert p.name in MODEL_IMPORTERS, f"{p.name} imports {sorted(hit)}"


def test_no_exception_handler_registration_outside_problem_py() -> None:
    for p in api_files():
        if p.name == "problem.py":
            continue
        text = p.read_text(encoding="utf-8")
        assert "exception_handler" not in text and "add_exception_handler" not in text, p.name


def test_no_test_seams_and_no_env_readers() -> None:
    for p in api_files():
        text = p.read_text(encoding="utf-8")
        for needle in ("dependency_overrides", "PYTEST_CURRENT_TEST", "os.environ", "getenv",
                       "import tests", "from tests"):
            assert needle not in text, f"{p.name} contains {needle}"


def test_no_signing_and_no_text_of_the_decide_entry_point() -> None:
    for p in api_files():
        text = p.read_text(encoding="utf-8")
        assert ".sign(" not in text and "maybe_checkpoint" not in text, p.name
        assert not re.search(r"\bdecide\(", text), p.name


def test_routers_have_no_body_or_query_parameters() -> None:
    allowed_ann = {"Request", "Principal", "str", "None"}
    for p in sorted(ROUTERS.glob("*.py")):
        tree = ast.parse(p.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in {"Body", "Query", "Form", "File"}, p.name
            if isinstance(node, ast.AsyncFunctionDef | ast.FunctionDef):
                for a in node.args.args:
                    ann = ast.unparse(a.annotation) if a.annotation else "None"
                    assert ann in allowed_ann, f"{p.name}:{node.name}({a.arg}: {ann})"


def test_create_app_signature_is_pinned() -> None:
    tree = ast.parse((API / "main.py").read_text(encoding="utf-8"))
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "create_app")
    assert [a.arg for a in fn.args.args] == ["settings"]
    assert ast.unparse(fn.args.args[0].annotation) == "Settings | None"
    assert ast.unparse(fn.args.defaults[0]) == "None"


def test_api_package_exists_with_expected_modules() -> None:
    names = {p.name for p in api_files()}
    for need in ("main.py", "problem.py", "middleware.py", "bodies.py", "auth.py", "deps.py",
                 "scoping.py", "idempotency.py", "admission.py", "revoke_recorder.py",
                 "validation.py", "ledger_io.py", "startup.py", "limits.py", "logging.py",
                 "state.py", "ports.py", "scan_status.py", "wiring.py"):
        assert need in names, need
    for r in ("health.py", "engagements.py", "scans.py", "ledger.py"):
        assert (ROUTERS / r).exists(), r


@pytest.mark.parametrize("builder", ["engagement_created", "engagement_rejected",
                                     "engagement_revoked", "scan_created", "scan_rejected",
                                     "scan_gate_error"])
def test_payload_builders_end_with_sanitize(builder: str) -> None:
    tree = ast.parse((API / "ledger_io.py").read_text(encoding="utf-8"))
    fn = next((n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == builder), None)
    assert fn is not None, builder
    last = fn.body[-1]
    assert isinstance(last, ast.Return) and isinstance(last.value, ast.Call)
    assert ast.unparse(last.value.func) == "sanitize"
