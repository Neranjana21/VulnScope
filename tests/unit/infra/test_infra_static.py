# ruff: noqa: E501
"""S1-S5 (docs/gates/slice0-plan.md 3.10.1): cheap static tripwires over the real repo files.

They are tripwires, not controls: the controls are the runtime guard G1,
``verify_effective_privileges`` and the independent oracle in ``tests/stress/db/``.
The checking logic lives in ``tests/unit/infra/static_checks.py`` (so the stress-tester can feed
it adversarial fixtures); it is imported lazily inside each test (GR-STR-20) so a missing module
turns each test red on its own instead of aborting collection. No database, no network.
"""
from __future__ import annotations

import importlib
import re
import subprocess
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
MIGRATIONS = sorted((REPO_ROOT / "alembic" / "versions").glob("*.py"))
INIT_SQL = REPO_ROOT / "infra" / "postgres" / "init-roles.sql"
WRAPPER = REPO_ROOT / "infra" / "postgres" / "00-init-roles.sh"
COMPOSE = REPO_ROOT / "docker-compose.dev.yml"

S3_FORBIDDEN = [
    r"\b(grant|revoke)\b",
    r"default\s+privileges",
    r"\bdo\s+\$",
    r"\bexecute\b",
    r"\bin\s+role\b",
    r"\bto\s+public\b",
]
S4_FORBIDDEN = [r"default\s+privileges", r"grant\s+all", r"\bto\s+public\b", r"get_x_argument"]


def _checks() -> ModuleType:
    return importlib.import_module("static_checks")


def _normalised(text: str) -> str:
    return re.sub(r"\s+", " ", text).lower()


def _strip_comments(path: Path, text: str) -> str:
    marker = "--" if path.suffix == ".sql" else "#"
    return "\n".join(line.split(marker, 1)[0] for line in text.splitlines())


def test_there_is_at_least_one_migration() -> None:
    assert MIGRATIONS, "no migration files found under alembic/versions"


@pytest.mark.parametrize("path", MIGRATIONS, ids=[p.name for p in MIGRATIONS])
def test_s1_s2_s4_every_migration_passes_the_source_tripwires(path: Path) -> None:
    violations = _checks().check_migration_source(path.read_text(encoding="utf-8"))
    assert violations == []


def test_s3_init_roles_sql_passes_the_tripwires() -> None:
    violations = _checks().check_init_sql(INIT_SQL.read_text(encoding="utf-8"))
    assert violations == []


def test_s5_wrapper_script_passes_the_tripwires() -> None:
    violations = _checks().check_wrapper_sh(WRAPPER.read_text(encoding="utf-8"))
    assert violations == []


def test_s3_no_grant_revoke_or_privilege_words_anywhere_under_infra_or_compose() -> None:
    files = [p for p in (REPO_ROOT / "infra").rglob("*") if p.is_file()] + [COMPOSE]
    assert COMPOSE.is_file() and len(files) > 1
    hits = []
    for path in files:
        text = _normalised(_strip_comments(path, path.read_text(encoding="utf-8")))
        hits += [
            f"{path.relative_to(REPO_ROOT)}: /{pattern}/"
            for pattern in S3_FORBIDDEN
            if re.search(pattern, text)
        ]
    assert hits == []


def test_s4_no_privilege_shortcut_or_cli_seam_anywhere_under_alembic() -> None:
    files = [
        p for p in (REPO_ROOT / "alembic").rglob("*")
        if p.is_file() and "__pycache__" not in p.parts
    ]
    assert files
    hits = []
    for path in files:
        text = _normalised(path.read_text(encoding="utf-8", errors="replace"))
        hits += [
            f"{path.relative_to(REPO_ROOT)}: /{pattern}/"
            for pattern in S4_FORBIDDEN
            if re.search(pattern, text)
        ]
    assert hits == []


def test_s5_wrapper_is_committed_executable() -> None:
    if not (REPO_ROOT / ".git").exists():
        pytest.skip("not a git checkout")
    proc = subprocess.run(
        ["git", "ls-files", "--stage", "--", "infra/postgres/00-init-roles.sh"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr[-300:]
    assert proc.stdout.split(" ", 1)[0] == "100755", "00-init-roles.sh must be committed with mode 100755"
