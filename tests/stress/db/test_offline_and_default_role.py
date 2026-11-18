# ruff: noqa: E501
"""Stress #10: ``--sql`` refusal, APP_ROLE versus init-roles.sql, no -x seam in alembic/. R1.

None of these touch a database. The offline run uses a dummy loopback URL; offline mode never
connects (and pre-fix it prints SQL and exits 0, which is what makes the first test red).
"""
from __future__ import annotations

import os
import re
import subprocess
import sys

import vulnscope_db_plugin as kit

DUMMY_URL = "postgresql+asyncpg://nobody:nopass@127.0.0.1:5432/vulnscope_stress_00000000"


def test_offline_sql_mode_is_refused_with_a_clear_message() -> None:
    kit.assert_lab_url(DUMMY_URL)
    env = {**os.environ, kit.ADMIN_ENV: DUMMY_URL, "PYTHONPATH": str(kit.REPO_ROOT / "src")}
    proc = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head", "--sql"],
        cwd=kit.REPO_ROOT, env=env, capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode != 0, "OFFLINE: 'alembic upgrade head --sql' must fail for 0001 (it exited 0)"
    assert "cannot run with --sql" in proc.stderr, (
        f"OFFLINE: refusal message missing; stderr tail: {proc.stderr[-400:]}"
    )
    assert "GRANT" not in proc.stdout.upper(), "OFFLINE: SQL containing GRANT was printed"


def test_app_role_constant_equals_the_role_created_by_init_roles_sql() -> None:
    mg = kit.lazy("vulnscope.db.migration_grants")
    sql = (kit.REPO_ROOT / "infra" / "postgres" / "init-roles.sql").read_text(encoding="utf-8")
    sql = "\n".join(ln for ln in sql.splitlines() if not ln.strip().startswith("--"))
    created = re.findall(r"CREATE\s+ROLE\s+([A-Za-z0-9_\"]+)", sql, flags=re.IGNORECASE)
    assert created == ["vulnscope_app"], f"init-roles.sql must create exactly vulnscope_app, found {created}"
    assert mg.APP_ROLE == "vulnscope_app" == created[0], f"APP_ROLE {mg.APP_ROLE!r} != init-roles.sql role"


def test_no_command_line_seam_for_the_app_role_exists_under_alembic() -> None:
    # The bare substring "app_role" is NOT a needle: the required call
    # ``mg.require_app_role(bind, mg.APP_ROLE)`` in 0001_initial.py contains it. Only patterns that
    # denote a way to NAME another role from the command line, config or environment count.
    # (env.py legitimately reads VULNSCOPE_MIGRATION_DATABASE_URL, so environ only counts near ROLE.)
    seam = re.compile(
        r"get_x_argument|x_arguments|-x |-x\s+\w*role|config\.cmd_opts|(?:environ|getenv)[^\n]*role",
        re.IGNORECASE,
    )
    offenders = []
    for path in (kit.REPO_ROOT / "alembic").rglob("*"):
        if path.is_file() and path.suffix in {".py", ".ini", ".mako"}:
            text = path.read_text(encoding="utf-8")
            for m in seam.finditer(text):
                offenders.append(f"{path.relative_to(kit.REPO_ROOT)}: {m.group(0)!r}")
    assert not offenders, "a way to name another role exists: " + "; ".join(offenders)


def test_app_role_is_not_overridable_through_the_environment() -> None:
    """No env var may feed APP_ROLE: grep the helper and alembic for os.environ near APP_ROLE."""
    mg = kit.lazy("vulnscope.db.migration_grants")
    src = (kit.REPO_ROOT / "src" / "vulnscope" / "db" / "migration_grants.py").read_text(encoding="utf-8")
    assert "environ" not in src and "getenv" not in src, "migration_grants reads the environment"
    assert isinstance(mg.APP_ROLE, str)
