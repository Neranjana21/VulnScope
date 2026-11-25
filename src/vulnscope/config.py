"""Application configuration, loaded from ``VULNSCOPE_*`` environment
variables via pydantic-settings (CLAUDE.md "config via env").

No secret ever gets a hardcoded default here -- ``database_url`` has no
default at all, so a real deployment must supply
``VULNSCOPE_DATABASE_URL`` explicitly (see ``.env.example`` for the
dev-only placeholder shape).
"""
from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """All ``VULNSCOPE_*`` environment variables this slice needs.

    Field -> env var mapping (via ``env_prefix``):
    - ``database_url`` -> ``VULNSCOPE_DATABASE_URL`` (app role, asyncpg DSN);
      ``repr=False`` so ``repr(Settings)`` can never print the DSN password (T6)
    - ``max_rps_per_host`` -> ``VULNSCOPE_MAX_RPS_PER_HOST``
      (docs/io-contracts.md "Engagement": default 10)
    - ``max_window_days`` -> ``VULNSCOPE_MAX_WINDOW_DAYS``
      (docs/io-contracts.md "Engagement": default 90)
    - ``enable_lab`` -> ``VULNSCOPE_ENABLE_LAB`` (D8: lab profile gate)
    - ``lab_cidr`` -> ``VULNSCOPE_LAB_CIDR`` (D8: lab profile subnet)
    - ``ledger_signing_key_file`` -> ``VULNSCOPE_LEDGER_SIGNING_KEY_FILE``: a PATH to the
      ledger signing key (never key bytes, never logged). Unset means verify-only startup.
    """

    model_config = SettingsConfigDict(env_prefix="VULNSCOPE_", extra="ignore")

    database_url: str | None = Field(default=None, repr=False)
    max_rps_per_host: float = 10.0
    max_window_days: int = 90
    enable_lab: bool = False
    lab_cidr: str | None = None
    ledger_signing_key_file: Path | None = None


# ---- API admission (AuthGate) overrides: DE-03, DE-04 ----------------------------------------
# All environment reading for the API layer lives here (``vulnscope.api`` never touches the
# environment). ``Settings`` above is unchanged. Values are typed, bounded and fail closed.
ADMISSION_ENV_PREFIX = "VULNSCOPE_API_"
# The engine pool is 5 plus 10 overflow (db/session.py): the auth slots must leave room for the
# handler transactions that run after authentication.
MAX_AUTH_SLOTS_TOTAL = 14


class AdmissionConfigError(ValueError):
    """Invalid ``VULNSCOPE_API_AUTH_*`` setting. Names the fields only, never the values."""


class AdmissionSettings(BaseModel):
    """At least one reserved slot is mandatory: zero would remove the protection that keeps
    revocation reachable during an authentication flood (N-03)."""

    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)

    auth_inflight: int = Field(ge=1, le=12)
    auth_reserved: int = Field(ge=1, le=4)
    auth_queue_wait_s: float = Field(ge=0.05, le=15.0)
    auth_db_budget_s: float = Field(ge=0.2, le=10.0)

    @model_validator(mode="after")
    def _fits_the_pool(self) -> AdmissionSettings:
        if self.auth_inflight + self.auth_reserved > MAX_AUTH_SLOTS_TOTAL:
            raise ValueError("auth slots exceed the connection pool")
        return self


def load_admission_overrides(
    defaults: Mapping[str, int | float], environ: Mapping[str, str] | None = None
) -> AdmissionSettings:
    """Return the four AuthGate settings: ``defaults`` overridden by validated
    ``VULNSCOPE_API_AUTH_*`` variables. Raises ``AdmissionConfigError`` (field names only)."""
    env = os.environ if environ is None else environ
    raw: dict[str, object] = {}
    for name in AdmissionSettings.model_fields:
        value = env.get(ADMISSION_ENV_PREFIX + name.upper())
        raw[name] = value if value is not None else defaults[name]
    try:
        cfg = AdmissionSettings.model_validate(raw)
    except ValidationError as exc:
        fields = sorted({".".join(str(p) for p in err["loc"]) or "auth_slots"
                         for err in exc.errors()})
        raise AdmissionConfigError(
            "invalid API admission settings: " + ", ".join(fields)) from None
    return cfg
