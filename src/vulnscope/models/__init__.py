"""``vulnscope.models`` package.

Importing this package -- directly, or transitively via ``from
vulnscope.models.base import Base`` (Python always runs a package's
``__init__.py`` before any of its submodules) -- registers every
SQLAlchemy model's table onto ``Base.metadata``. This is what makes
``alembic/env.py``'s ``target_metadata = Base.metadata`` complete without
``env.py`` needing to import each model module itself.
"""
from vulnscope.models import (  # noqa: F401
    api_key,
    engagement,
    evidence,
    finding,
    idempotency,
    ledger_models,
    org,
    scan,
    user,
)
from vulnscope.models.base import Base

__all__ = ["Base"]
