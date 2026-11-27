"""Step 1b end to end against a disposable task database.

The "lab app" is a fake listener that THIS test process binds on 127.0.0.1:3000. If the
port cannot be bound the test fails and nothing is sent. No real lab app is contacted.
"""

from __future__ import annotations

import asyncio
import hashlib
import importlib
import re
from pathlib import Path
from typing import Any

import pytest
from devpath import LABEL
from devpath.stub import RunningStub
from lab_fake import OK, FakeLabApp, silent_port
from sqlalchemy.ext.asyncio import AsyncEngine

from vulnscope.config import Settings
from vulnscope.ledger.postgres_backend import PostgresChainBackend
from vulnscope.models.evidence import Evidence
from vulnscope.models.finding import Finding
from vulnscope.policy.clock import SystemClock
from vulnscope.policy.decide_and_record import decide_and_record
from vulnscope.policy.ratelimit import InMemoryRateLimitStore
from vulnscope.policy.types import Action
from vulnscope.report.render import render_report
from vulnscope.validate.types import HEADER_NAMES

pytestmark = pytest.mark.integration

CANARY = "canary-7f3a9c"
SECURE = (
    "HTTP/1.1 200 OK\r\n"
    + "".join(f"{name}: {CANARY}\r\n" for name in HEADER_NAMES)
    + "Content-Length: 0\r\nConnection: close\r\n\r\n"
).encode()


def _module(name: str) -> Any:
    return importlib.import_module(name)


class Case:
    def __init__(self, settings: Settings, engine: AsyncEngine, seeded: Any) -> None:
        self.settings = settings
        self.engine = engine
        self.ids: dict[str, Any] = {
            "settings": settings,
            "engine": engine,
            "engagement_id": seeded.engagement_id,
            "org_id": seeded.org_id,
        }
        self.engagement_id: str = seeded.engagement_id
        self.chain = f"engagement:{seeded.engagement_id}"

    async def run(self) -> Any:
        juice = _module("devpath.targets").JUICE_SHOP
        return await _module("devpath.runner").run_check(stub=juice, **self.ids)

    async def revoke(self) -> None:
        await _module("devpath.engagement").revoke_engagement(**self.ids)

    async def entries(self) -> list[Any]:
        return [e async for e in PostgresChainBackend(self.engine).read(self.chain)]

    async def assert_no_finding(self) -> None:
        from sqlalchemy import select
        from sqlalchemy.ext.asyncio import AsyncSession

        async with AsyncSession(self.engine) as session:
            for model in (Finding, Evidence):
                query = select(model).where(model.engagement_id == self.engagement_id)
                assert (await session.execute(query)).scalars().all() == []
        assert not {"evidence", "finding.transition"} & {e.kind for e in await self.entries()}


@pytest.fixture
async def case(settings: Settings, engine: AsyncEngine) -> Case:
    juice = _module("devpath.targets").JUICE_SHOP
    seeded = await _module("devpath.engagement").seed_engagement(
        settings=settings, engine=engine, target=juice
    )
    return Case(settings, engine, seeded)


async def test_the_engagement_statement_is_the_operator_attestation(case: Case) -> None:
    engagement = _module("devpath.engagement")
    statement = engagement.LAB_APP_STATEMENT
    for phrase in ("operator attests", "port 3000", "local Juice Shop", "cannot verify"):
        assert phrase in statement
    [created] = await case.entries()
    basis = created.payload["authorization_basis"]
    assert basis["statement_sha256"] == hashlib.sha256(statement.encode()).hexdigest()
    assert set(created.payload) == {
        "schema_version",
        "engagement_id",
        "profile",
        "authorization_basis",
        "scope_sha256",
        "window_not_before",
        "window_not_after",
        "rate_limit_mrps",
        "execution_path",
    }


async def test_issue_is_recorded_and_the_report_is_for_the_lab_app(case: Case) -> None:
    with FakeLabApp() as app:
        result = await case.run()
    assert (result.outcome, result.decision_seqs, len(app.requests)) == ("issue", (1,), 1)
    assert [e.kind for e in await case.entries()] == [
        "engagement.created",
        "policy.decision",
        "finding.transition",
        "evidence",
        "finding.transition",
    ]
    model = await _module("devpath.runner").collect_report(
        outcome=result.outcome, target_kind="lab_app", **case.ids
    )
    assert (model.integrity.status, list(model.evidence_checks.values())) == ("ok", [True])
    document = render_report(model)
    assert "lab app on 127.0.0.1:3000" in document and "stub" not in document.lower()


async def test_revoke_between_decision_and_send_sends_nothing(
    case: Case, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_append = PostgresChainBackend.append

    async def append(self: Any, chain_id: str, kind: str, *args: Any, **kwargs: Any) -> Any:
        entry = await real_append(self, chain_id, kind, *args, **kwargs)
        if kind == "policy.decision":
            await case.revoke()
        return entry

    monkeypatch.setattr(PostgresChainBackend, "append", append)
    with FakeLabApp() as app:
        result = await case.run()
    assert (result.outcome, result.detail) == ("revoked", "revoked_before_send")
    assert app.requests == []
    await case.assert_no_finding()


async def test_revoke_during_a_stalled_response_cancels_the_send(case: Case) -> None:
    with FakeLabApp(None) as app:
        task = asyncio.create_task(case.run())
        assert await asyncio.to_thread(app.got_request.wait, 5.0)
        await case.revoke()
        result = await asyncio.wait_for(task, 4.0)
        assert await asyncio.to_thread(app.client_closed.wait, 2.0)
    assert (result.outcome, result.finding_id, result.decision_seqs) == ("revoked", None, (1,))
    await case.assert_no_finding()


async def test_revoke_between_response_and_write_stops_the_write(
    case: Case, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = _module("devpath.runner")
    real = runner._send_watched

    async def revoke_after_response(*args: Any, **kwargs: Any) -> Any:
        sent = await real(*args, **kwargs)
        assert sent is not None and sent[1] is not None
        await case.revoke()
        return sent

    monkeypatch.setattr(runner, "_send_watched", revoke_after_response)
    with FakeLabApp():
        result = await case.run()
    assert (result.outcome, result.detail) == ("revoked", "revoked_before_write")
    await case.assert_no_finding()


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.2:3000/",
        "http://10.0.0.5:3000/",
        "http://169.254.169.254:3000/",
        "http://host.docker.internal:3000/",
    ],
)
async def test_a_real_denial_is_in_the_real_ledger(case: Case, url: str) -> None:
    engagement = _module("devpath.engagement")
    async with __import__("sqlalchemy").ext.asyncio.AsyncSession(case.engine) as session:
        row = await engagement.load_engagement(session, case.engagement_id, case.ids["org_id"])
        view = engagement.build_view(row, case.settings)
    clock = SystemClock()
    decision = await decide_and_record(
        Action(kind="http", target=url, adapter="a"),
        view,
        clock.now(),
        resolver=_module("devpath.transport")._RefusingResolver(),
        clock=clock,
        rate_limit_store=InMemoryRateLimitStore(),
        chain_backend=PostgresChainBackend(case.engine),
        actor="system",
        lab_enabled=True,
        lab_cidr=None,
    )
    assert decision.allowed is False and decision.ledger_seq == 1
    assert (await case.entries())[1].payload["allowed"] is False


# --- the command (sync tests: it owns its event loop) ---


def _run_command(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> tuple[int, str]:
    code = _module("devpath.step1b").main(["--out", str(tmp_path)])
    captured = capsys.readouterr()
    assert captured.err == ""
    lines = captured.out.splitlines()
    assert lines[0] == LABEL and lines[-1] == LABEL
    for forbidden in ("postgresql", "http://", CANARY, str(tmp_path)):
        assert forbidden not in captured.out, forbidden
    return code, captured.out


def test_command_end_to_end(
    settings: Settings, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    with FakeLabApp(OK) as app:
        code, out = _run_command(tmp_path, capsys)
    assert code == 0, out
    assert len(app.requests) == 1 and app.requests[0].startswith(b"HEAD / HTTP/1.1\r\n")
    for needle in (
        "lab_isolation=not_verified",
        "step=lab_app outcome=issue finding_status=confirmed",
        "rule_id=ALLOW",
        "header=x-frame-options verdict=absent",
        "step=verify result=ok",
        "evidence_checks_ok=true",
        "report_check=ok report_problems=0",
        "report_written=true",
    ):
        assert needle in out, needle
    document = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert LABEL in document and "lab isolation not verified" in document
    assert "stub" not in document.lower() and "MISMATCH" not in document


def test_command_with_all_headers_present_exits_zero_without_a_finding(
    settings: Settings, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    with FakeLabApp(SECURE):
        code, out = _run_command(tmp_path, capsys)
    assert code == 0, out
    assert "step=lab_app outcome=no_issue finding_status=none finding_id=none" in out
    assert CANARY not in (tmp_path / "report.html").read_text(encoding="utf-8")


def test_command_does_not_follow_a_redirect(
    settings: Settings, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    with RunningStub("secure") as second:
        raw = (
            f"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{second.port}/{CANARY}\r\n"
            "Content-Length: 0\r\n\r\n"
        ).encode()
        with FakeLabApp(raw) as app:
            code, out = _run_command(tmp_path, capsys)
        assert second.connections_before_now() == 0
    assert (code, len(app.requests)) == (1, 1)
    assert "outcome=inconclusive" in out and "observation=redirect_not_followed" in out
    assert "finding_id=none" in out


def test_command_with_nothing_listening_exits_non_zero_without_a_finding(
    settings: Settings, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    with silent_port():
        code, out = _run_command(tmp_path, capsys)
    assert code == 1, out
    assert re.search(r"step=lab_app outcome=inconclusive finding_status=none finding_id=none", out)
    assert "observation=connection_error" in out and "header=" not in out
    assert "kind=evidence" not in out and "kind=finding.transition" not in out
