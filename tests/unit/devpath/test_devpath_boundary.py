"""ADR-0013 Q2 proof: ``devpath`` is not importable from the API and is not in the built package.

Static checks only plus one clean-interpreter import. No network.
"""

from __future__ import annotations

import ast
import os
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "src"
DEVPATH = ROOT / "devpath"


def _imports(source: str) -> set[str]:
    """Every imported module name, plus literal names given to dynamic importers."""
    found: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            found.add(module)
            found.update(f"{module}.{alias.name}".lstrip(".") for alias in node.names)
        elif isinstance(node, ast.Call) and node.args:
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
            first = node.args[0]
            if name in ("import_module", "__import__", "run_module", "find_spec"):
                if isinstance(first, ast.Constant) and isinstance(first.value, str):
                    found.add(first.value)
    return found


def _hits(imports: set[str], *tops: str) -> set[str]:
    return {name for name in imports if name.split(".")[0] in tops}


def _files(base: Path) -> list[Path]:
    files = sorted(base.rglob("*.py"))
    assert files, f"nothing to scan under {base.name}"
    return files


def test_scanner_catches_planted_imports() -> None:
    for planted in (
        "import devpath",
        "import devpath.transport as t",
        "from devpath import transport",
        "from devpath.transport import guarded_head",
        "import importlib\nimportlib.import_module('devpath.transport')",
        "__import__('devpath')",
    ):
        assert _hits(_imports(planted), "devpath"), planted


def test_nothing_under_src_imports_devpath() -> None:
    offenders = [
        str(path.relative_to(ROOT))
        for path in _files(SRC)
        if _hits(_imports(path.read_text(encoding="utf-8")), "devpath")
    ]
    assert offenders == []
    assert any(path.is_relative_to(SRC / "vulnscope" / "api") for path in _files(SRC))


def test_importing_every_api_module_does_not_load_devpath() -> None:
    code = (
        "import importlib, pkgutil, sys, importlib.util\n"
        "assert importlib.util.find_spec('devpath') is not None  # importable, so this means it\n"
        "import vulnscope.api as api\n"
        "names = [m.name for m in pkgutil.walk_packages(api.__path__, 'vulnscope.api.')]\n"
        "assert 'vulnscope.api.main' in names\n"
        "for name in names:\n"
        "    importlib.import_module(name)\n"
        "print(sorted(m for m in sys.modules if m.split('.')[0] == 'devpath'))\n"
        "print(api.__file__)\n"
    )
    env = {"PYTHONPATH": os.pathsep.join([str(SRC), str(ROOT)]), "PATH": os.environ["PATH"]}
    done = subprocess.run(
        [sys.executable, "-c", code], env=env, cwd=ROOT, capture_output=True, text=True, timeout=60
    )
    assert done.returncode == 0, done.stderr[-2000:]
    loaded, api_file = done.stdout.splitlines()
    assert loaded == "[]"
    assert Path(api_file).is_relative_to(SRC)


def test_wheel_build_config_excludes_devpath() -> None:
    """Config-level proof (hatchling is not installed, so no wheel is built here)."""
    config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert config["build-system"]["build-backend"] == "hatchling.build"
    assert config["tool"]["hatch"]["build"] == {
        "targets": {"wheel": {"packages": ["src/vulnscope"]}}
    }  # no force-include, include or extra target that could pull devpath in
    assert not (ROOT / "hatch.toml").exists()
    assert not (ROOT / "hatch_build.py").exists()
    assert "devpath" not in str(config["project"])  # no script or entry point
    assert DEVPATH.is_dir()
    assert not DEVPATH.is_relative_to(SRC)
    assert not list(SRC.rglob("devpath*"))
    assert not [p for p in SRC.rglob("*") if p.is_symlink()]


def test_devpath_never_imports_decide_or_an_http_client() -> None:
    for path in _files(DEVPATH):
        imports = _imports(path.read_text(encoding="utf-8"))
        assert not _hits(imports, "httpx", "requests", "urllib", "http", "aiohttp"), path.name
        assert not {i for i in imports if i.startswith("vulnscope.policy.decide.")}, path.name
        assert "vulnscope.policy.decide" not in imports, path.name
        assert "vulnscope.policy.resolver.SystemResolver" not in imports, path.name


def test_only_transport_and_stub_use_socket_and_only_transport_uses_h11() -> None:
    imports = {p.name: _imports(p.read_text(encoding="utf-8")) for p in _files(DEVPATH)}
    assert {n for n, i in imports.items() if _hits(i, "socket")} == {"stub.py", "transport.py"}
    assert {n for n, i in imports.items() if _hits(i, "h11")} == {"transport.py"}


def test_src_gains_no_socket_or_h11_user() -> None:
    """``policy/resolver.py`` (getaddrinfo) predates Step 1; nothing else may appear."""
    users = {
        path.relative_to(SRC / "vulnscope").as_posix()
        for path in _files(SRC)
        if _hits(_imports(path.read_text(encoding="utf-8")), "socket", "h11")
    }
    assert users == {"policy/resolver.py"}


def test_pure_packages_import_no_networking() -> None:
    for package in ("validate", "report"):
        for path in _files(SRC / "vulnscope" / package):
            imports = _imports(path.read_text(encoding="utf-8"))
            assert not _hits(
                imports, "socket", "ssl", "http", "httpx", "h11", "urllib", "asyncio", "subprocess"
            ), path.name
