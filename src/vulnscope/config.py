"""Application configuration, loaded from ``VULNSCOPE_*`` environment
variables via pydantic-settings (CLAUDE.md "config via env").

No secret ever gets a hardcoded default here -- ``database_url`` has no
default at all, so a real deployment must supply
``VULNSCOPE_DATABASE_URL`` explicitly (see ``.env.example`` for the
dev-only placeholder shape).
"""
from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """All ``VULNSCOPE_*`` environment variables this slice needs.

    Field -> env var mapping (via ``env_prefix``):
    - ``database_url`` -> ``VULNSCOPE_DATABASE_URL`` (app role, asyncpg DSN)
    - ``max_rps_per_host`` -> ``VULNSCOPE_MAX_RPS_PER_HOST``
      (docs/io-contracts.md "Engagement": default 10)
    - ``max_window_days`` -> ``VULNSCOPE_MAX_WINDOW_DAYS``
      (docs/io-contracts.md "Engagement": default 90)
    - ``enable_lab`` -> ``VULNSCOPE_ENABLE_LAB`` (D8: lab profile gate)
    - ``lab_cidr`` -> ``VULNSCOPE_LAB_CIDR`` (D8: lab profile subnet)
    """

    model_config = SettingsConfigDict(env_prefix="VULNSCOPE_", extra="ignore")

    database_url: str | None = None
    max_rps_per_host: float = 10.0
    max_window_days: int = 90
    enable_lab: bool = False
    lab_cidr: str | None = None
