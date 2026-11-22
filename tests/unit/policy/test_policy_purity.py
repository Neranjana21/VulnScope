"""Structural purity of every policy/*.py (SEC-A13, RC4, design section 6)."""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest

import vulnscope.policy as policy_pkg

POLICY_DIR = Path(policy_pkg.__file__).resolve().parent
EXPECTED_FILES = {
    "__init__.py",
    "types.py",
    "clock.py",
    "resolver.py",
    "ratelimit.py",
    "denylist.py",
    "private_ranges.py",
    "scope.py",
    "target.py",
    "decide.py",
    "decide_and_record.py",
    "engagement_check.py",
}

BANNED_ALWAYS = {
    "sqlalchemy",
    "fastapi",
    "starlette",
    "pydantic",
    "httpx",
    "requests",
    "urllib",
    "urllib3",
    "http",
    "ssl",
    "subprocess",
    "ctypes",
    "importlib",
    "os",
    "sys",
    "logging",
    "pickle",
    "marshal",
    "multiprocessing",
    "shutil",
    "tempfile",
    "pathlib",
    "builtins",
    "vulnscope.models",
    "vulnscope.api",
    "vulnscope.db",
    "vulnscope.config",
}
NETWORK_ONLY_IN_RESOLVER = {"socket", "concurrent", "selectors", "select", "ftplib", "smtplib"}
ASYNCIO_ALLOWED = {"decide_and_record.py", "resolver.py"}
LEDGER_ALLOWED = {"vulnscope.ledger.chain", "vulnscope.ledger.types", "vulnscope.ledger.canonical"}
BANNED_CALLS = {"eval", "exec", "open", "__import__", "compile", "input", "print", "breakpoint"}
BANNED_ATTRS = {
    "open_connection",
    "open_unix_connection",
    "start_server",
    "start_unix_server",
    "create_connection",
    "create_server",
    "create_datagram_endpoint",
    "run_in_executor",
    "create_subprocess_exec",
    "create_subprocess_shell",
    "sock_connect",
    "sock_sendall",
    "getenv",
    "environ",
    "putenv",
}
MUTABLE_CALLS = {"list", "dict", "set", "defaultdict", "OrderedDict", "deque", "bytearray"}


def violations(source: str, filename: str) -> list[str]:
    tree = ast.parse(source)
    out: list[str] = []
    for node in ast.walk(tree):
        modules: list[str] = []
        if isinstance(node, ast.Import):
            modules = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            modules = [node.module or ""]
            if node.module == "vulnscope.ledger":
                out.append("ledger package import (name the module)")
            for alias in node.names:
                if alias.name in BANNED_ATTRS or (
                    alias.name == "getaddrinfo" and filename != "resolver.py"
                ):
                    out.append(f"banned import name {alias.name}")
        for m in modules:
            top = m.split(".")[0]
            if any(m == b or m.startswith(b + ".") for b in BANNED_ALWAYS):
                out.append(f"banned import {m}")
            if top in NETWORK_ONLY_IN_RESOLVER and filename != "resolver.py":
                out.append(f"network import {m} outside resolver.py")
            if top == "asyncio" and filename not in ASYNCIO_ALLOWED:
                out.append(f"asyncio import in {filename}")
            if m.startswith("vulnscope.ledger") and m not in LEDGER_ALLOWED:
                out.append(f"ledger import {m}")
            if m == "vulnscope.ledger.canonical" and filename != "decide_and_record.py":
                out.append("canonical import outside decide_and_record.py")
        if isinstance(node, ast.Global):
            out.append("global statement")
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in BANNED_CALLS
        ):
            out.append(f"banned call {node.func.id}")
        if isinstance(node, ast.Attribute):
            if node.attr in BANNED_ATTRS:
                out.append(f"banned attribute {node.attr}")
            if node.attr == "getaddrinfo" and filename != "resolver.py":
                out.append("getaddrinfo outside resolver.py")
            if node.attr in {"environ", "getenv"}:
                out.append("environment access")
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.args.kwarg is not None:
            if node.name in {"decide", "decide_and_record"}:
                out.append("**kwargs on a decision entry point")
    for stmt in tree.body:
        value = None
        if isinstance(stmt, ast.Assign | ast.AnnAssign):
            value = stmt.value
        if isinstance(
            value, ast.List | ast.Dict | ast.Set | ast.ListComp | ast.DictComp | ast.SetComp
        ):
            out.append("module-level mutable container")
        if (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Name)
            and value.func.id in MUTABLE_CALLS
        ):
            out.append("module-level mutable container")
    return out


def _files() -> list[Path]:
    return sorted(POLICY_DIR.glob("*.py"))


def test_exact_file_set_exists_no_skips() -> None:
    present = {p.name for p in _files()}
    assert EXPECTED_FILES <= present, sorted(EXPECTED_FILES - present)
    assert present <= EXPECTED_FILES, sorted(present - EXPECTED_FILES)


@pytest.mark.parametrize("path", _files(), ids=lambda p: p.name)
def test_file_is_pure(path: Path) -> None:
    assert violations(path.read_text(encoding="utf-8"), path.name) == []


@pytest.mark.parametrize(
    "mutation",
    [
        "import os\nx = os.getenv('X')",
        "import socket",
        "from socket import getaddrinfo",
        "import asyncio\nasyncio.open_connection",
        "import subprocess",
        "import importlib",
        "eval('1')",
        "open('f')",
        "X = []",
        "X = {}",
        "X = set()",
        "def f():\n    global y\n    y = 1",
        "from vulnscope.ledger.verify import verify",
        "from vulnscope.models.engagement import Engagement",
        "import logging",
        "def decide(a, **kw): ...",
        "print('x')",
    ],
)
def test_mutations_turn_the_check_red(mutation: str) -> None:
    assert violations(mutation, "ratelimit.py") != []


def test_resolver_may_use_socket_and_executors() -> None:
    assert (
        violations(
            "import socket\nfrom concurrent.futures import ThreadPoolExecutor", "resolver.py"
        )
        == []
    )
    assert violations("import socket", "scope.py") != []


def test_signature_allowlist() -> None:
    from vulnscope.policy.decide import decide

    sig = inspect.signature(decide)
    assert list(sig.parameters) == [
        "action",
        "engagement",
        "now",
        "resolver",
        "clock",
        "rate_limit_store",
        "lab_enabled",
        "lab_cidr",
    ]
    assert all(p.kind is not inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values())
    kinds = {n: p.kind for n, p in sig.parameters.items()}
    assert all(
        kinds[n] is inspect.Parameter.KEYWORD_ONLY
        for n in ("resolver", "clock", "rate_limit_store", "lab_enabled", "lab_cidr")
    )


def test_decide_and_record_signature_allowlist() -> None:
    from vulnscope.policy.decide_and_record import decide_and_record

    sig = inspect.signature(decide_and_record)
    assert list(sig.parameters) == [
        "action",
        "engagement",
        "now",
        "resolver",
        "clock",
        "rate_limit_store",
        "chain_backend",
        "actor",
        "lab_enabled",
        "lab_cidr",
    ]
    assert all(p.kind is not inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values())


def test_engagement_check_imports_only_siblings() -> None:
    tree = ast.parse((POLICY_DIR / "engagement_check.py").read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom | ast.Import):
            names = (
                [node.module or ""]
                if isinstance(node, ast.ImportFrom)
                else [a.name for a in node.names]
            )
            for n in names:
                assert not n.startswith(("vulnscope.ledger", "socket", "asyncio")), n


def test_package_does_not_export_decide() -> None:
    assert not hasattr(policy_pkg, "decide") or inspect.ismodule(policy_pkg.decide)
    assert "decide" not in getattr(policy_pkg, "__all__", ())
