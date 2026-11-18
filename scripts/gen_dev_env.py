#!/usr/bin/env python3
"""Generate .env for the Slice 0 dev/test PostgreSQL stack (docker-compose.dev.yml).

Creates two independent, cryptographically random passwords (one per DB
role -- vulnscope_migrator, vulnscope_app) using the stdlib `secrets`
module, and writes `.env` at the repository root with file mode 0o600,
set atomically at creation (via os.open), not via a separate chmod
afterward -- so the file is never briefly world-readable.

Neither password is ever printed, logged, or returned from this script.
Refuses to overwrite an existing .env (O_EXCL) so a second run can't
silently clobber one a developer already edited by hand.

Not executed by anything automatically. A developer (or the orchestrator,
with explicit approval) runs this manually:

    python3 scripts/gen_dev_env.py
"""
from __future__ import annotations

import os
import secrets
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ENV_PATH = REPO_ROOT / ".env"


def main() -> None:
    migrator_password = secrets.token_urlsafe(32)
    app_password = secrets.token_urlsafe(32)

    lines = [
        f"POSTGRES_PASSWORD={migrator_password}",
        f"VULNSCOPE_APP_PASSWORD={app_password}",
        f"VULNSCOPE_DATABASE_URL=postgresql+asyncpg://vulnscope_app:{app_password}@127.0.0.1:5432/vulnscope",
        f"VULNSCOPE_MIGRATION_DATABASE_URL=postgresql+asyncpg://vulnscope_migrator:{migrator_password}@127.0.0.1:5432/vulnscope",
        f"VULNSCOPE_TEST_APP_DATABASE_URL=postgresql+asyncpg://vulnscope_app:{app_password}@127.0.0.1:5432/vulnscope",
        "VULNSCOPE_MAX_RPS_PER_HOST=10",
        "VULNSCOPE_MAX_WINDOW_DAYS=90",
        "VULNSCOPE_ENABLE_LAB=0",
        "VULNSCOPE_LAB_CIDR=127.0.0.1/32",
    ]
    # Each entry is its own list item joined with a real newline -- no
    # escaped line-continuation characters anywhere, so every variable
    # lands on its own line in the file.
    content = "\n".join(lines) + "\n"

    try:
        fd = os.open(ENV_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise SystemExit(
            f"{ENV_PATH} already exists -- refusing to overwrite it. "
            "Remove or rename it first if you really want a fresh one."
        ) from None

    with os.fdopen(fd, "w") as f:
        f.write(content)

    print(f"{ENV_PATH} written with mode 600. Password values intentionally not printed.")


if __name__ == "__main__":
    main()
