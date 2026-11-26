"""STEP 1 DEVELOPMENT PATH: no gateway, no worker, not the security boundary.

One header check against our own stub (ADR-0013).

Rule 4: the engagement is re-read immediately before the decision (``guarded_head``); a
watcher cancels an in-flight send on revoke, and it starts only once the decision is
recorded, so a decision (including a denial) is never lost to it; before any write the
engagement row is locked ``FOR UPDATE``, must be active and inside its window, and the
lock is held through the writes.

Ledger entries and rows are not atomic: a crash can leave an orphan entry, never a
silent row.
"""

from __future__ import annotations

import asyncio
import hashlib
import uuid
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from devpath import LABEL
from devpath.engagement import (
    EXECUTION_PATH,
    build_view,
    check_config,
    is_open,
    load_engagement,
)
from devpath.stub import RunningStub
from devpath.transport import (
    ADAPTER_PREFIX,
    SendFailed,
    TransportDeps,
    guarded_head,
)
from vulnscope.config import Settings
from vulnscope.ledger.canonical import JsonValue, sanitize_payload
from vulnscope.ledger.postgres_backend import PostgresChainBackend
from vulnscope.ledger.types import LedgerEntry
from vulnscope.ledger.verify import verify
from vulnscope.models.evidence import Evidence
from vulnscope.models.finding import Finding
from vulnscope.models.finding_state import can_transition
from vulnscope.models.schemas.common import uuid7
from vulnscope.models.schemas.finding import (
    UNSCORED,
    UNSCORED_UNKNOWN_INPUTS,
    CvssInfo,
    EvidenceView,
    FindingView,
    Priority,
    SourceAdapter,
)
from vulnscope.models.schemas.ledger import VerifyResponse
from vulnscope.policy.clock import SystemClock
from vulnscope.policy.ratelimit import InMemoryRateLimitStore
from vulnscope.policy.types import EngagementPolicyView, PolicyDecision, RuleId
from vulnscope.report.model import DecisionFact, EngagementFacts, ReportModel, ReportOutcome
from vulnscope.validate.evidence import build_evidence
from vulnscope.validate.security_headers import evaluate
from vulnscope.validate.types import CheckResult, HeaderResponse

WATCH_INTERVAL_S = 0.25
ADAPTER_NAME = "devpath.security_headers"
ADAPTER_VERSION = "1"
TITLE = "Security response headers missing"
TAXONOMY = ("security-headers",)
EVIDENCE_KIND = "http.response_header_presence"
EXPECTED = "all five allowlisted response headers present"
OBSERVED = "one or more allowlisted response headers absent"


@dataclass(frozen=True)
class RunOutcome:
    outcome: ReportOutcome
    decision_seqs: tuple[int, ...]
    finding_id: str | None
    detail: str | None = None  # closed vocabulary: a rule id or a fixed reason code


async def _watch(sending: asyncio.Event, still_permitted: Callable[[], Awaitable[bool]]) -> None:
    """Returns only when permission is gone. Idle until the decision has been recorded."""
    await sending.wait()
    while await still_permitted():
        await asyncio.sleep(WATCH_INTERVAL_S)


async def _send_watched(
    *,
    stub: RunningStub,
    fresh_view: Callable[[], Awaitable[EngagementPolicyView]],
    deps: TransportDeps,
    run_id: str,
    still_permitted: Callable[[], Awaitable[bool]],
) -> tuple[PolicyDecision, HeaderResponse | None] | None:
    """``None``: permission was withdrawn in flight and the send was cancelled. A failing
    permission poll also cancels the send, and raises (fail closed)."""
    sending = asyncio.Event()  # set by the sender after the recorded, pinned ALLOW
    send = asyncio.create_task(
        guarded_head(stub=stub, fresh_view=fresh_view, deps=deps, run_id=run_id, sending=sending)
    )
    watch = asyncio.create_task(_watch(sending, still_permitted))
    try:
        await asyncio.wait({send, watch}, return_when=asyncio.FIRST_COMPLETED)
        if send.done():
            return send.result()
        watch.result()
        return None
    finally:
        send.cancel()
        watch.cancel()
        await asyncio.gather(send, watch, return_exceptions=True)


async def _still_permitted(engine: AsyncEngine, engagement_id: str, org_id: str) -> bool:
    async with AsyncSession(engine) as session:
        row = await load_engagement(session, engagement_id, org_id)
        return row.status == "active" and is_open(row, SystemClock().now())


async def _chain(backend: PostgresChainBackend, engagement_id: str) -> list[LedgerEntry]:
    return [entry async for entry in backend.read(f"engagement:{engagement_id}")]


def _decision_seqs(entries: list[LedgerEntry], run_id: str) -> tuple[int, ...]:
    wanted = ADAPTER_PREFIX + run_id
    found = []
    for entry in entries:
        action = entry.payload.get("action")
        if entry.kind == "policy.decision" and isinstance(action, Mapping):
            if action.get("adapter") == wanted:
                found.append(entry.seq)
    return tuple(found)


async def run_check(
    *, settings: Settings, engine: AsyncEngine, engagement_id: str, org_id: str, stub: RunningStub
) -> RunOutcome:
    check_config(settings, engine)
    backend = PostgresChainBackend(engine)
    clock = SystemClock()
    run_id = uuid7()
    deps = TransportDeps(
        clock=clock,
        rate_limit_store=InMemoryRateLimitStore(),
        chain_backend=backend,
        lab_enabled=settings.enable_lab,
        lab_cidr=settings.lab_cidr,
    )

    async def fresh_view() -> EngagementPolicyView:
        async with AsyncSession(engine) as session:
            return build_view(await load_engagement(session, engagement_id, org_id), settings)

    try:
        sent = await _send_watched(
            stub=stub,
            fresh_view=fresh_view,
            deps=deps,
            run_id=run_id,
            still_permitted=lambda: _still_permitted(engine, engagement_id, org_id),
        )
    except SendFailed as failure:
        seq = failure.decision.ledger_seq
        assert seq is not None  # the sender refuses an unrecorded decision
        return RunOutcome("inconclusive", (seq,), None, failure.code)
    if sent is None:
        seqs = _decision_seqs(await _chain(backend, engagement_id), run_id)
        return RunOutcome("revoked", seqs, None, "revoked_in_flight")
    decision, response = sent
    if decision.ledger_seq is None:
        raise RuntimeError("unrecorded policy decision")
    seqs = (decision.ledger_seq,)
    if response is None:
        outcome: ReportOutcome = "revoked" if decision.rule_id is RuleId.REVOKED else "denied"
        return RunOutcome(outcome, seqs, None, decision.rule_id.value)
    result = evaluate(response)
    if result.outcome != "issue":
        return RunOutcome(result.outcome, seqs, None, result.reason)
    return await _record_issue(
        engine=engine,
        backend=backend,
        engagement_id=engagement_id,
        org_id=org_id,
        decision=decision,
        result=result,
    )


async def _record_issue(
    *,
    engine: AsyncEngine,
    backend: PostgresChainBackend,
    engagement_id: str,
    org_id: str,
    decision: PolicyDecision,
    result: CheckResult,
) -> RunOutcome:
    assert decision.ledger_seq is not None
    seqs = (decision.ledger_seq,)
    chain_id = f"engagement:{engagement_id}"
    adapter = SourceAdapter(name=ADAPTER_NAME, version=ADAPTER_VERSION)
    evidence = build_evidence(result)
    finding_id, evidence_id = uuid7(), uuid7()
    origin = decision.action.target
    asset_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"{engagement_id}|{origin}"))

    async with AsyncSession(engine) as session, session.begin():
        engagement = await load_engagement(session, engagement_id, org_id, lock=True)
        now = SystemClock().now()  # read after the lock is granted
        if engagement.status != "active":
            return RunOutcome("revoked", seqs, None, "revoked_before_write")
        if not is_open(engagement, now):
            return RunOutcome("denied", seqs, None, "window_closed_before_write")
        if not can_transition("candidate", "confirmed"):
            raise RuntimeError("finding state machine forbids candidate to confirmed")
        view = FindingView(
            id=finding_id,
            schema_version=1,
            org_id=org_id,
            engagement_id=engagement_id,
            asset_id=asset_id,
            title=TITLE,
            taxonomy=list(TAXONOMY),
            status="candidate",
            severity=None,
            evidence_ids=[],
            cvss=CvssInfo(version=UNSCORED, score=None, vector="", source="none", snapshot="none"),
            priority=Priority(
                band=UNSCORED,
                reasons=[],
                policy_version="none",
                unknown_inputs=list(UNSCORED_UNKNOWN_INPUTS),
            ),
            source_adapter=adapter,
            first_seen=now,
            last_seen=now,
        )

        async def append(kind: str, fields: dict[str, JsonValue]) -> LedgerEntry:
            payload: dict[str, JsonValue] = {
                "schema_version": 1,
                "finding_id": finding_id,
                "execution_path": EXECUTION_PATH,
                **fields,
            }
            return await backend.append(chain_id, kind, "system", sanitize_payload(payload), now)

        await append("finding.transition", {"from": None, "to": "candidate"})
        recorded = await append(
            "evidence",
            {
                "evidence_id": evidence_id,
                "content_sha256": evidence.content_sha256,
                "policy_version": decision.policy_version,
                "adapter": {"name": ADAPTER_NAME, "version": ADAPTER_VERSION},
                "decision_seq": decision.ledger_seq,
            },
        )
        evidence_view = EvidenceView(
            id=evidence_id,
            finding_id=finding_id,
            kind=EVIDENCE_KIND,
            redacted_excerpt=evidence.excerpt,
            content_sha256=evidence.content_sha256,
            expected=EXPECTED,
            observed=OBSERVED,
            policy_version=decision.policy_version,
            adapter=adapter,
            ledger_chain=chain_id,
            ledger_seq=recorded.seq,
            created_at=now,
        )
        finding = Finding(
            **view.model_dump(exclude={"schema_version", "first_seen", "last_seen"}),
            first_seen=now,
            last_seen=now,
            created_at=now,
            updated_at=now,
        )
        session.add(finding)
        await session.flush()  # bare foreign keys: the finding row must exist first
        session.add(
            Evidence(
                **evidence_view.model_dump(exclude={"created_at"}),
                org_id=org_id,
                engagement_id=engagement_id,
                created_at=now,
                updated_at=now,
            )
        )
        await session.flush()
        await append("finding.transition", {"from": "candidate", "to": "confirmed"})
        finding.status = "confirmed"
        finding.evidence_ids = [evidence_id]
    return RunOutcome("issue", seqs, finding_id)


def _evidence_agrees(
    row: Evidence,
    finding: Finding | None,
    chain_id: str,
    entries: list[LedgerEntry],
) -> bool:
    """Excerpt hash vs row vs ledger entry, and finding status vs its last transition."""
    by_seq = {entry.seq: entry for entry in entries}
    entry = by_seq.get(row.ledger_seq)
    if finding is None or entry is None or entry.kind != "evidence":
        return False
    recorded = entry.payload
    decision_seq = recorded.get("decision_seq")
    decision = by_seq.get(decision_seq) if isinstance(decision_seq, int) else None
    transitions = [
        e.payload.get("to")
        for e in entries
        if e.kind == "finding.transition" and e.payload.get("finding_id") == finding.id
    ]
    digest = hashlib.sha256(row.redacted_excerpt.encode("utf-8", "surrogatepass")).hexdigest()
    return (
        row.ledger_chain == chain_id
        and digest == row.content_sha256 == recorded.get("content_sha256")
        and recorded.get("evidence_id") == row.id
        and recorded.get("finding_id") == row.finding_id == finding.id
        and recorded.get("policy_version") == row.policy_version
        and recorded.get("adapter") == row.adapter
        and decision is not None
        and decision.kind == "policy.decision"
        and decision.payload.get("allowed") is True
        and bool(transitions)
        and transitions[-1] == finding.status
        and row.id in finding.evidence_ids
    )


def _finding_view(row: Finding) -> FindingView:
    names = set(FindingView.model_fields) - {"schema_version"}
    return FindingView.model_validate(
        {"schema_version": 1, **{name: getattr(row, name) for name in names}}
    )


def _evidence_view(row: Evidence) -> EvidenceView:
    return EvidenceView.model_validate(
        {name: getattr(row, name) for name in EvidenceView.model_fields}
    )


async def collect_report(
    *,
    settings: Settings,
    engine: AsyncEngine,
    engagement_id: str,
    org_id: str,
    outcome: ReportOutcome,
) -> ReportModel:
    check_config(settings, engine)
    backend = PostgresChainBackend(engine)
    chain_id = f"engagement:{engagement_id}"
    checked = await verify(chain_id, backend)
    entries = await _chain(backend, engagement_id)
    async with AsyncSession(engine) as session:
        engagement = await load_engagement(session, engagement_id, org_id)
        view = build_view(engagement, settings)
        findings = list(
            (
                await session.execute(
                    select(Finding)
                    .where(Finding.engagement_id == engagement_id, Finding.org_id == org_id)
                    .order_by(Finding.id)
                )
            ).scalars()
        )
        evidence = list(
            (
                await session.execute(
                    select(Evidence)
                    .where(Evidence.engagement_id == engagement_id, Evidence.org_id == org_id)
                    .order_by(Evidence.id)
                )
            ).scalars()
        )
    by_id = {row.id: row for row in findings}
    assert view.authorization_basis is not None
    return ReportModel(
        label=LABEL,
        engagement=EngagementFacts(
            engagement_id=view.engagement_id,
            org_id=view.org_id,
            profile=view.profile,
            status=view.status,
            scope_allow=view.scope_allow,
            scope_deny=view.scope_deny,
            window_not_before=view.window_not_before.isoformat(),
            window_not_after=view.window_not_after.isoformat(),
            approver=view.authorization_basis.approver,
            statement_sha256=view.authorization_basis.statement_sha256,
        ),
        policy_version=view.policy_version,
        decisions=tuple(
            DecisionFact(
                ledger_seq=entry.seq,
                allowed=entry.payload.get("allowed") is True,
                rule_id=str(entry.payload.get("rule_id")),
                reason=str(entry.payload.get("reason")),
            )
            for entry in entries
            if entry.kind == "policy.decision"
        ),
        findings=tuple(_finding_view(row) for row in findings),
        evidence=tuple(_evidence_view(row) for row in evidence),
        evidence_checks={
            row.id: _evidence_agrees(row, by_id.get(row.finding_id), chain_id, entries)
            for row in evidence
        },
        outcome=outcome,
        verify=VerifyResponse(
            result=checked.result,
            first_bad_seq=checked.first_bad_seq,
            records=checked.records,
            checkpoint_seq=checked.checkpoint_seq,
        ),
    )
