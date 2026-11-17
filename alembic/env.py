"""Async Alembic env.py (docs/gates/slice0-plan.md Section 3.8 -- the
standard Alembic "async cookbook" pattern, hand-adapted to this repo's
layout). Migration authors still write plain, synchronous-looking
``upgrade()``/``downgrade()`` functions with ``op.create_table(...)`` etc.
in each revision file under ``alembic/versions/`` -- nothing about writing
a migration changes; the async plumbing is confined entirely to this
file.

Migration role vs. application role: migrations run authenticated as
``vulnscope_migrator`` (the schema owner, design C/Section 3.10) via
``VULNSCOPE_MIGRATION_DATABASE_URL``, never the credential the running app
uses (``VULNSCOPE_DATABASE_URL`` / ``vulnscope_app``). The running FastAPI
app process must never hold migrator credentials.
"""
from __future__ import annotations

import asyncio
import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import AsyncEngine, async_engine_from_config

from vulnscope.models.base import Base  # Alembic target_metadata

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Migration role, never the app role -- see module docstring above.
# alembic.ini's own sqlalchemy.url is left blank/placeholder; the real URL
# (and the vulnscope_migrator credential) come from this env var at
# invocation time, not from a file.
config.set_main_option(
    "sqlalchemy.url", os.environ["VULNSCOPE_MIGRATION_DATABASE_URL"]
)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(url=url, target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    connectable: AsyncEngine = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,  # migrations are short-lived; no pooling needed
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
