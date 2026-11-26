"""STEP 1 DEVELOPMENT PATH: no gateway, no worker, not the security boundary.

Config refusals, the fixed seed engagement, revoke and the policy view. Rows go through
the existing ORM models; ledger entries through the existing ledger backend.

Seeding is NOT API admission: it runs the same schema and ``validate_engagement_targets``
check, with self-attested authorization.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.engine import URL, make_url
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from vulnscope.config import Settings
from vulnscope.ledger.canonical import sanitize_payload
from vulnscope.ledger.postgres_backend import PostgresChainBackend
from vulnscope.models.engagement import Engagement
from vulnscope.models.schemas.common import uuid7
from vulnscope.models.schemas.engagement import (
    Authorization,
    EngagementCreateRequest,
    Scope,
    Targets,
    Window,
)
from vulnscope.policy.clock import SystemClock
from vulnscope.policy.denylist import compute_policy_version
from vulnscope.policy.engagement_check import validate_engagement_targets
from vulnscope.policy.types import AuthorizationBasis, EngagementPolicyView

EXECUTION_PATH = "step1-dev"
SEED_ORG_ID = "step1-dev-org"
SEED_APPROVER = "step1-dev-operator"
SEED_STATEMENT = "Self-attested: the only target is this process's own loopback stub."
_TASK_DB = re.compile(r"vulnscope_task[a-z]_[0-9a-f]{8}", re.ASCII)


class ConfigRefused(Exception):
    """``code`` is from a closed set. Never carries a URL or any setting value."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _parse_url(text: str) -> URL | None:
    try:
        return make_url(text)
    except Exception:  # noqa: BLE001 - the parser's message can echo the URL
        return None


def require_task_database(settings: Settings) -> str:
    """The settings-only refusals. No I/O. Returns the database URL (never print it)."""
    if settings.enable_lab is not True:
        raise ConfigRefused("lab_not_enabled")
    if settings.lab_cidr is not None:
        raise ConfigRefused("lab_cidr_set")
    if not settings.database_url:
        raise ConfigRefused("database_not_set")
    parsed = _parse_url(settings.database_url)
    if parsed is None:
        raise ConfigRefused("database_url_invalid")
    if parsed.query:  # a query parameter might override what is checked here
        raise ConfigRefused("database_url_has_query")
    if not _TASK_DB.fullmatch(parsed.database or ""):
        raise ConfigRefused("database_not_task")
    return settings.database_url


def check_config(settings: Settings, engine: AsyncEngine) -> None:
    """Called first by every function that touches the database. Can only refuse."""
    if engine.url != _parse_url(require_task_database(settings)):
        raise ConfigRefused("engine_mismatch")


async def load_engagement(
    session: AsyncSession, engagement_id: str, org_id: str, *, lock: bool = False
) -> Engagement:
    """Always filtered by organisation; ``lock`` takes ``SELECT ... FOR UPDATE``."""
    query = select(Engagement).where(Engagement.id == engagement_id, Engagement.org_id == org_id)
    if lock:
        query = query.with_for_update()
    return (await session.execute(query)).scalar_one()


def window_of(row: Engagement) -> tuple[datetime, datetime]:
    window = Window.model_validate(row.scope["window"])
    return window.not_before, window.not_after


def is_open(row: Engagement, now: datetime) -> bool:
    not_before, not_after = window_of(row)
    return not_before <= now <= not_after


def build_view(row: Engagement, settings: Settings) -> EngagementPolicyView:
    scope = Scope.model_validate(row.scope)
    authorization = Authorization.model_validate(row.authorization)
    if row.profile not in ("standard", "lab"):
        raise ValueError("unknown engagement profile")
    return EngagementPolicyView(
        engagement_id=row.id,
        org_id=row.org_id,
        profile="lab" if row.profile == "lab" else "standard",
        status=row.status,
        scope_allow=tuple(scope.allow),
        scope_deny=tuple(scope.deny),
        expected_ip_ranges=tuple(scope.expected_ip_ranges),
        rate_limit_rps=scope.rate_limit_rps,
        window_not_before=scope.window.not_before,
        window_not_after=scope.window.not_after,
        policy_version=compute_policy_version(
            lab_enabled=settings.enable_lab, lab_cidr=settings.lab_cidr
        ),
        authorization_basis=AuthorizationBasis(
            confirmed=authorization.confirmed,
            approver=authorization.approver,
            statement_sha256=_sha256(authorization.statement),
        ),
    )


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _template(now: datetime) -> EngagementCreateRequest:
    return EngagementCreateRequest(
        schema_version=1,
        name="step1-dev-loopback-stub",
        profile="lab",
        targets=Targets(ip_ranges=["127.0.0.1/32"]),
        scope=Scope(
            allow=["127.0.0.1"],
            rate_limit_rps=5.0,
            window=Window(
                not_before=now - timedelta(minutes=1), not_after=now + timedelta(hours=1)
            ),
        ),
        authorization=Authorization(
            confirmed=True, statement=SEED_STATEMENT, approver=SEED_APPROVER
        ),
    )


class SeededEngagement:
    def __init__(self, engagement_id: str, org_id: str) -> None:
        self.engagement_id = engagement_id
        self.org_id = org_id


async def seed_engagement(*, settings: Settings, engine: AsyncEngine) -> SeededEngagement:
    """Ledger entry first, then the row: a crash can leave an entry, never a silent row."""
    check_config(settings, engine)
    now = SystemClock().now()
    request = _template(now)
    issues = validate_engagement_targets(
        domains=request.targets.domains,
        ip_ranges=request.targets.ip_ranges,
        allow=request.scope.allow,
        deny=request.scope.deny,
        expected_ip_ranges=request.scope.expected_ip_ranges,
        profile=request.profile,
        lab_enabled=settings.enable_lab,
        lab_cidr=settings.lab_cidr,
    )
    if issues:
        raise ConfigRefused("seed_targets_rejected")
    engagement_id = uuid7()
    scope = request.scope.model_dump(mode="json")
    payload = sanitize_payload(
        {
            "schema_version": 1,
            "engagement_id": engagement_id,
            "profile": request.profile,
            "authorization_basis": {
                "confirmed": True,
                "approver_sha256": _sha256(SEED_APPROVER),
                "statement_sha256": _sha256(SEED_STATEMENT),
            },
            "scope_sha256": _sha256(json.dumps(scope, sort_keys=True)),
            "window_not_before": request.scope.window.not_before.isoformat(),
            "window_not_after": request.scope.window.not_after.isoformat(),
            "rate_limit_mrps": 5000,
            "execution_path": EXECUTION_PATH,
        }
    )
    await PostgresChainBackend(engine).append(
        f"engagement:{engagement_id}", "engagement.created", "system", payload, now
    )
    async with AsyncSession(engine) as session, session.begin():
        session.add(
            Engagement(
                id=engagement_id,
                org_id=SEED_ORG_ID,
                name=request.name,
                profile=request.profile,
                status="active",
                targets=request.targets.model_dump(mode="json"),
                scope=scope,
                authorization=request.authorization.model_dump(mode="json"),
                identities=[],
                ownership_rules=[],
                asset_tags=[],
                created_at=now,
                updated_at=now,
            )
        )
    return SeededEngagement(engagement_id, SEED_ORG_ID)


async def revoke_engagement(
    *, settings: Settings, engine: AsyncEngine, engagement_id: str, org_id: str
) -> None:
    """Effect first, record second (as ADR-0006). Used by the integration tests only."""
    check_config(settings, engine)
    now = SystemClock().now()
    async with AsyncSession(engine) as session, session.begin():
        row = await load_engagement(session, engagement_id, org_id, lock=True)
        if row.status != "active":
            return
        row.status = "revoked"
        row.revoked_at = now
        row.revoked_reason = "step1 development revoke"
    await PostgresChainBackend(engine).append(
        f"engagement:{engagement_id}",
        "engagement.revoked",
        "system",
        sanitize_payload(
            {
                "schema_version": 1,
                "engagement_id": engagement_id,
                "revoked_at": now.isoformat(),
                "execution_path": EXECUTION_PATH,
            }
        ),
        now,
    )
