"""Step 1 end to end against a disposable task database and our own loopback stubs."""

from __future__ import annotations

import asyncio
import hashlib
import importlib
import logging
import sys
import uuid
from collections.abc import Iterator
from typing import Any

import pytest
from devpath import LABEL, transport
from devpath.stub import RunningStub
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from vulnscope.config import Settings
from vulnscope.ledger.postgres_backend import PostgresChainBackend
from vulnscope.models.engagement import Engagement
from vulnscope.models.evidence import Evidence
from vulnscope.models.finding import Finding
from vulnscope.models.ledger_models import LedgerEntryRow
from vulnscope.report.render import render_report
from vulnscope.validate.types import HEADER_NAMES

pytestmark = pytest.mark.integration

CANARY = "canary-7f3a9c"


class _Lazy:
    """Imported on first use, so that every test is collected and fails on its own."""

    def __init__(self, name: str) -> None:
        self._name = name

    def __getattr__(self, attribute: str) -> Any:
        return getattr(importlib.import_module(self._name), attribute)


engagement: Any = _Lazy("devpath.engagement")
runner: Any = _Lazy("devpath.runner")


@pytest.fixture
def stub() -> Iterator[RunningStub]:
    with RunningStub("insecure") as running:
        yield running


class Case:
    def __init__(self, settings: Settings, engine: AsyncEngine, seeded: Any) -> None:
        self.ids: dict[str, Any] = {
            "settings": settings,
            "engine": engine,
            "engagement_id": seeded.engagement_id,
            "org_id": seeded.org_id,
        }
        self.engine = engine
        self.engagement_id: str = seeded.engagement_id
        self.chain = f"engagement:{seeded.engagement_id}"

    async def run(self, stub: RunningStub) -> Any:
        return await runner.run_check(stub=stub, **self.ids)

    async def revoke(self) -> None:
        await engagement.revoke_engagement(**self.ids)

    async def entries(self) -> list[Any]:
        return [e async for e in PostgresChainBackend(self.engine).read(self.chain)]

    async def kinds(self) -> list[str]:
        return [e.kind for e in await self.entries()]

    async def rows(self, model: Any) -> list[Any]:
        async with AsyncSession(self.engine) as session:
            query = select(model).where(model.engagement_id == self.engagement_id)
            return list((await session.execute(query)).scalars())

    async def assert_no_finding(self) -> None:
        assert await self.rows(Finding) == []
        assert await self.rows(Evidence) == []
        assert not {"evidence", "finding.transition"} & set(await self.kinds())

    async def report(self, outcome: Any = "issue") -> Any:
        return await runner.collect_report(outcome=outcome, target_kind="own_stub", **self.ids)


@pytest.fixture
async def case(settings: Settings, engine: AsyncEngine) -> Case:
    seeded = await engagement.seed_engagement(settings=settings, engine=engine)
    return Case(settings, engine, seeded)


async def test_issue_writes_rows_and_ledger_in_order(case: Case, stub: RunningStub) -> None:
    result = await case.run(stub)
    assert (result.outcome, result.detail, result.decision_seqs) == ("issue", None, (1,))
    entries = await case.entries()
    assert [(e.seq, e.kind) for e in entries] == [
        (0, "engagement.created"),
        (1, "policy.decision"),
        (2, "finding.transition"),
        (3, "evidence"),
        (4, "finding.transition"),
    ]
    assert entries[1].payload["rule_id"] == "ALLOW"
    assert entries[1].payload["action"]["adapter"].startswith("devpath.security_headers@1|job=")
    assert (entries[2].payload["from"], entries[2].payload["to"]) == (None, "candidate")
    assert (entries[4].payload["from"], entries[4].payload["to"]) == ("candidate", "confirmed")
    assert all(entries[i].payload["execution_path"] == "step1-dev" for i in (2, 3, 4))

    [finding] = await case.rows(Finding)
    [evidence] = await case.rows(Evidence)
    assert finding.id == result.finding_id
    assert (finding.status, finding.evidence_ids) == ("confirmed", [evidence.id])
    assert finding.severity is None
    assert finding.cvss["score"] is None and finding.cvss["version"] == "unscored"
    assert (evidence.ledger_chain, evidence.ledger_seq) == (case.chain, 3)
    digest = hashlib.sha256(evidence.redacted_excerpt.encode()).hexdigest()
    assert evidence.content_sha256 == digest == entries[3].payload["content_sha256"]
    assert entries[3].payload["evidence_id"] == evidence.id
    assert entries[3].payload["finding_id"] == finding.id
    assert entries[3].payload["decision_seq"] == 1
    assert "excerpt" not in str(entries[3].payload)
    assert stub.request_count == 1

    model = await case.report()
    assert model.verify.result == "ok" and model.verify.records == 5
    assert model.evidence_checks == {evidence.id: True}
    assert (model.integrity.status, model.integrity.problems) == ("ok", ())
    document = render_report(model)
    assert "Evidence cross-check: " in document and "MISMATCH" not in document
    assert LABEL in document


async def test_secure_stub_writes_no_finding(case: Case) -> None:
    with RunningStub("secure") as secure:
        result = await case.run(secure)
    assert (result.outcome, result.finding_id) == ("no_issue", None)
    await case.assert_no_finding()
    assert await case.kinds() == ["engagement.created", "policy.decision"]
    assert (await case.report("no_issue")).integrity.status == "ok"


async def test_redirect_is_inconclusive_and_nothing_is_followed(case: Case) -> None:
    with RunningStub("secure") as second:
        raw = (
            f"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{second.port}/{CANARY}\r\n"
            "Content-Length: 0\r\n\r\n"
        ).encode()
        with RunningStub(raw_response=raw) as first:
            result = await case.run(first)
            assert first.connections_before_now() == 1
        assert second.connections_before_now() == 0
    assert (result.outcome, result.detail) == ("inconclusive", "redirect_not_followed")
    await case.assert_no_finding()
    assert await case.kinds() == ["engagement.created", "policy.decision"]
    assert CANARY not in str([e.payload for e in await case.entries()])


async def test_revoked_first_is_recorded_and_sends_nothing(case: Case, stub: RunningStub) -> None:
    await case.revoke()
    result = await case.run(stub)
    assert (result.outcome, result.detail) == ("revoked", "REVOKED")
    assert stub.connections_before_now() == 0
    entries = await case.entries()
    assert [e.kind for e in entries] == [
        "engagement.created",
        "engagement.revoked",
        "policy.decision",
    ]
    assert (entries[2].payload["allowed"], entries[2].payload["rule_id"]) == (False, "REVOKED")
    await case.assert_no_finding()


async def test_watcher_starts_only_after_the_decision_is_recorded(
    case: Case, stub: RunningStub, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Revoke lands while the ALLOW is still being appended, and the append is slow (longer
    than two poll intervals). A watcher already running would cancel and lose the record."""
    events: list[str] = []
    real_append = PostgresChainBackend.append
    real_poll = importlib.import_module("devpath.runner")._still_permitted

    async def append(self: Any, chain_id: str, kind: str, *args: Any, **kwargs: Any) -> Any:
        if kind != "policy.decision":
            return await real_append(self, chain_id, kind, *args, **kwargs)
        await case.revoke()
        await asyncio.sleep(0.7)
        entry = await real_append(self, chain_id, kind, *args, **kwargs)
        events.append("recorded")
        return entry

    async def poll(*args: Any, **kwargs: Any) -> Any:
        events.append("poll")
        return await real_poll(*args, **kwargs)

    monkeypatch.setattr(PostgresChainBackend, "append", append)
    monkeypatch.setattr("devpath.runner._still_permitted", poll)
    result = await case.run(stub)
    # The pre-send re-check refuses, so nothing is sent and the watcher never starts.
    assert events == ["recorded"]
    assert stub.connections_before_now() == 0
    assert (result.outcome, result.decision_seqs) == ("revoked", (2,))
    assert result.detail == "revoked_before_send"
    decision = (await case.entries())[2]
    assert (decision.kind, decision.payload["rule_id"]) == ("policy.decision", "ALLOW")
    await case.assert_no_finding()


async def test_revoke_committed_between_decision_and_send_sends_nothing(
    case: Case, stub: RunningStub, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_append = PostgresChainBackend.append

    async def append(self: Any, chain_id: str, kind: str, *args: Any, **kwargs: Any) -> Any:
        entry = await real_append(self, chain_id, kind, *args, **kwargs)
        if kind == "policy.decision":
            await case.revoke()  # committed after the decision, before the send
        return entry

    monkeypatch.setattr(PostgresChainBackend, "append", append)
    result = await case.run(stub)
    assert (stub.connections_before_now(), stub.request_count) == (0, 0)
    assert (result.outcome, result.detail) == ("revoked", "revoked_before_send")
    assert (result.finding_id, result.decision_seqs) == (None, (1,))
    entries = await case.entries()
    assert [e.kind for e in entries] == [
        "engagement.created",
        "policy.decision",
        "engagement.revoked",
    ]
    assert entries[1].payload["allowed"] is True
    await case.assert_no_finding()


async def test_revoke_during_a_stalled_response_cancels_the_send(case: Case) -> None:
    loop = asyncio.get_running_loop()
    with RunningStub("stall") as stalled:
        task = asyncio.create_task(case.run(stalled))
        assert await asyncio.to_thread(stalled.wait_for_requests, 1, 5.0)
        await case.revoke()
        started = loop.time()
        result = await asyncio.wait_for(task, 4.0)
        # Well inside the 5 s send cap, so the watcher stopped it, not the timeout.
        assert loop.time() - started < 2.0
        assert await asyncio.to_thread(stalled.wait_for_client_close)
    assert (result.outcome, result.finding_id, result.decision_seqs) == ("revoked", None, (1,))
    await case.assert_no_finding()


async def test_revoke_between_response_and_write_stops_the_write(
    case: Case, stub: RunningStub, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = runner._send_watched

    async def revoke_after_response(*args: Any, **kwargs: Any) -> Any:
        sent = await real(*args, **kwargs)
        assert sent is not None and sent[1] is not None
        await case.revoke()
        return sent

    monkeypatch.setattr("devpath.runner._send_watched", revoke_after_response)
    result = await case.run(stub)
    assert (result.outcome, result.finding_id) == ("revoked", None)
    assert stub.request_count == 1
    await case.assert_no_finding()


async def test_row_lock_is_held_through_the_writes(
    case: Case, stub: RunningStub, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = PostgresChainBackend.append
    revokes: list[asyncio.Task[None]] = []
    blocked: list[bool] = []

    async def append(self: Any, chain_id: str, kind: str, *args: Any, **kwargs: Any) -> Any:
        if kind == "evidence" and not revokes:
            revokes.append(asyncio.create_task(case.revoke()))
            done, _ = await asyncio.wait(revokes, timeout=0.5)
            blocked.append(not done)
        return await real(self, chain_id, kind, *args, **kwargs)

    monkeypatch.setattr(PostgresChainBackend, "append", append)
    result = await case.run(stub)
    await asyncio.wait_for(revokes[0], 5.0)
    assert blocked == [True]
    assert result.outcome == "issue"
    assert (await case.kinds())[-2:] == ["finding.transition", "engagement.revoked"]


@pytest.mark.parametrize(
    ("raw", "detail"),
    [
        (None, "timeout"),
        (b"HTTP/1.1 200 OK\r\nX-Pad: " + b"a" * 20_000 + b"\r\n\r\n", "headers_too_large"),
    ],
    ids=["timeout", "oversized"],
)
async def test_failed_send_is_inconclusive(
    case: Case, monkeypatch: pytest.MonkeyPatch, raw: bytes | None, detail: str
) -> None:
    monkeypatch.setattr(transport, "TOTAL_TIMEOUT_S", 0.5)
    with RunningStub("stall", raw_response=raw) as hostile:
        result = await case.run(hostile)
    assert (result.outcome, result.detail, result.decision_seqs) == ("inconclusive", detail, (1,))
    await case.assert_no_finding()


_AUDIT: list[tuple[str, tuple[Any, ...]]] = []
_AUDITING = [False]


def _audit_hook(event: str, args: tuple[Any, ...]) -> None:
    if _AUDITING[0] and event in ("socket.connect", "socket.getaddrinfo"):
        _AUDIT.append((event, args))


sys.addaudithook(_audit_hook)  # cannot be removed; inert unless _AUDITING is set


async def test_only_the_stub_and_database_are_contacted(
    case: Case, stub: RunningStub, monkeypatch: pytest.MonkeyPatch
) -> None:
    with RunningStub("secure") as trap:
        for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "all_proxy"):
            monkeypatch.setenv(name, f"http://127.0.0.1:{trap.port}")
        await case.engine.dispose()  # so database connects happen inside the audit window
        stub_port = stub.port
        _AUDIT.clear()
        _AUDITING[0] = True
        try:
            result = await case.run(stub)
            await case.report()
        finally:
            _AUDITING[0] = False
        assert trap.connections_before_now() == 0
    assert result.outcome == "issue"
    connects = {tuple(args[1][:2]) for event, args in _AUDIT if event == "socket.connect"}
    assert connects == {("127.0.0.1", stub_port), ("127.0.0.1", 5432)}
    lookups = {args[0] for event, args in _AUDIT if event == "socket.getaddrinfo"}
    assert lookups <= {"127.0.0.1"}


async def _edit(case: Case, model: Any, **changes: Any) -> None:
    async with AsyncSession(case.engine) as session:
        query = select(model).where(model.engagement_id == case.engagement_id)
        row = (await session.execute(query)).scalar_one()
        for name, value in changes.items():
            setattr(row, name, value)
        await session.commit()


def _codes(report: Any) -> set[str]:
    return {problem.code for problem in report.integrity.problems}


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


@pytest.mark.parametrize(
    ("model", "changes"),
    [
        (Evidence, {"redacted_excerpt": "x-frame-options: present"}),
        (
            Evidence,
            {"redacted_excerpt": "edited", "content_sha256": _sha("edited")},
        ),
        (Evidence, {"content_sha256": "0" * 64}),
        (Evidence, {"policy_version": "edited"}),
        (Evidence, {"ledger_seq": 1}),
        (Finding, {"status": "false_positive"}),
        (Finding, {"evidence_ids": []}),
        (Finding, {"title": "edited"}),
        (Evidence, {"kind": "edited"}),
        (Evidence, {"expected": "edited"}),
        (Evidence, {"observed": None}),
    ],
    ids=[
        "excerpt",
        "excerpt-and-hash",
        "hash",
        "policy",
        "seq",
        "status",
        "evidence-ids",
        "title",
        "kind",
        "expected",
        "observed",
    ],
)
async def test_edited_rows_are_reported_as_mismatch(
    case: Case, stub: RunningStub, model: Any, changes: dict[str, Any]
) -> None:
    await case.run(stub)
    await _edit(case, model, **changes)
    report = await case.report()
    assert list(report.evidence_checks.values()) == [False]
    assert "MISMATCH" in render_report(report)
    assert report.integrity.status == "mismatch"
    assert "evidence_row_differs" in _codes(report)
    assert report.verify.result == "ok"  # the chain itself was not touched


@pytest.mark.parametrize("status_line", ["200 REASON", "302 REASON"])
async def test_no_header_value_reaches_rows_report_or_output(
    case: Case,
    status_line: str,
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    caplog.set_level(logging.DEBUG)
    lines = ["HTTP/1.1 " + status_line.replace("REASON", CANARY)]
    lines += [f"{name}: {CANARY}" for name in HEADER_NAMES[:3]]
    lines += [f"Location: http://{CANARY}.invalid/{CANARY}", f"Set-Cookie: s={CANARY}"]
    lines += [f"X-{CANARY}: {CANARY}", "Content-Length: 0"]
    raw = ("\r\n".join(lines) + "\r\n\r\n" + CANARY).encode()
    with RunningStub(raw_response=raw) as hostile:
        result = await case.run(hostile)
    document = render_report(await case.report(result.outcome))
    dumped: list[str] = []
    async with AsyncSession(case.engine) as session:
        for model, column in (
            (Engagement, Engagement.id),
            (Finding, Finding.engagement_id),
            (Evidence, Evidence.engagement_id),
            (LedgerEntryRow, LedgerEntryRow.chain_id),
        ):
            wanted = case.chain if model is LedgerEntryRow else case.engagement_id
            rows = (await session.execute(select(model).where(column == wanted))).scalars().all()
            assert rows or (result.outcome != "issue" and model in (Finding, Evidence))
            dumped += [
                repr({c.name: getattr(row, c.key) for c in model.__table__.columns}) for row in rows
            ]
    captured = capsys.readouterr()
    everything = "".join([*dumped, document, repr(result), captured.out, captured.err, caplog.text])
    assert CANARY not in everything


async def _delete(case: Case, *models: Any) -> None:
    """ORM deletes in the given order, as the app role (it holds DELETE on these tables)."""
    async with AsyncSession(case.engine) as session, session.begin():
        for model in models:
            query = select(model).where(model.engagement_id == case.engagement_id)
            await session.delete((await session.execute(query)).scalar_one())
            await session.flush()


@pytest.mark.parametrize(
    ("models", "codes"),
    [
        ((Evidence,), {"evidence_row_missing", "confirmed_without_evidence"}),
        (
            (Evidence, Finding),
            {"evidence_row_missing", "finding_row_missing", "confirmed_without_evidence"},
        ),
    ],
    ids=["evidence", "finding-and-evidence"],
)
async def test_deleted_rows_are_reported(
    case: Case, stub: RunningStub, models: tuple[Any, ...], codes: set[str]
) -> None:
    await case.run(stub)
    await _delete(case, *models)
    report = await case.report()
    assert report.evidence == () and report.evidence_checks == {}
    assert (report.integrity.status, _codes(report)) == ("mismatch", codes)
    assert "MISMATCH" in render_report(report)
    assert report.verify.result == "ok"


@pytest.mark.parametrize(
    ("model", "codes"),
    [(Finding, {"finding_row_unrecorded"}), (Evidence, {"evidence_row_unrecorded"})],
    ids=["finding", "evidence"],
)
async def test_a_row_without_a_ledger_entry_is_reported(
    case: Case, stub: RunningStub, model: Any, codes: set[str]
) -> None:
    await case.run(stub)
    async with AsyncSession(case.engine) as session, session.begin():
        query = select(model).where(model.engagement_id == case.engagement_id)
        row = (await session.execute(query)).scalar_one()
        copy = {c.key: getattr(row, c.key) for c in model.__table__.columns}
        copy["id"] = str(uuid.uuid4())
        session.add(model(**copy))
    report = await case.report()
    assert (report.integrity.status, _codes(report)) == ("mismatch", codes)
    assert "MISMATCH" in render_report(report)


async def test_a_bounded_ledger_read_is_reported_as_incomplete(
    case: Case, stub: RunningStub, monkeypatch: pytest.MonkeyPatch
) -> None:
    await case.run(stub)
    monkeypatch.setattr("devpath.runner.MAX_LEDGER_ENTRIES", 4, raising=False)
    report = await case.report()
    assert report.integrity.status == "incomplete"
    assert report.integrity.incomplete_reasons == ("ledger_read_bounded",)
    assert "check incomplete" in render_report(report)
