"""Runner safety without a database: config refusals and the in-flight revoke watcher."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any

import pytest
from devpath import engagement, runner, transport
from devpath.stub import RunningStub
from sqlalchemy.engine import make_url
from test_devpath_transport import Harness

from vulnscope.config import Settings
from vulnscope.ledger.types import VerifyResult
from vulnscope.policy.types import RuleId

PASSWORD = "canary-pw-7f3a9c"


def url(database: str = "vulnscope_tasks_0123abcd", suffix: str = "") -> str:
    return f"postgresql+asyncpg://app:{PASSWORD}@127.0.0.1:5432/{database}{suffix}"


def make_settings(**changes: Any) -> Settings:
    values: dict[str, Any] = {"database_url": url(), "enable_lab": True, "lab_cidr": None}
    values.update(changes)
    return Settings(**values)


class UntouchableEngine:
    """Only ``url`` may be read: anything else would be database use."""

    def __init__(self, database_url: str) -> None:
        self.url = make_url(database_url)

    def __getattr__(self, name: str) -> Any:
        raise AssertionError("the database was used despite a refusal")


def test_the_task_database_config_is_accepted() -> None:
    engagement.check_config(make_settings(), UntouchableEngine(url()))  # type: ignore[arg-type]


REFUSALS = [
    ({"enable_lab": False}, "lab_not_enabled"),
    ({"lab_cidr": "127.0.0.0/8"}, "lab_cidr_set"),
    ({"lab_cidr": ""}, "lab_cidr_set"),
    ({"database_url": None}, "database_not_set"),
    ({"database_url": "not a url " + PASSWORD}, "database_url_invalid"),
    ({"database_url": url("vulnscope")}, "database_not_task"),
    ({"database_url": url("vulnscope_tasks_0123ABCD")}, "database_not_task"),
    ({"database_url": url("vulnscope_tasks_0123abc")}, "database_not_task"),
    ({"database_url": url("vulnscope_tasks_0123abcd_x")}, "database_not_task"),
    ({"database_url": url(suffix="?database=vulnscope")}, "database_url_has_query"),
    ({"database_url": url(suffix="?ssl=disable")}, "database_url_has_query"),
]


@pytest.mark.parametrize(("changes", "code"), REFUSALS)
async def test_every_entry_point_refuses_before_database_or_stub_use(
    changes: dict[str, Any], code: str
) -> None:
    bad = make_settings(**changes)
    engine: Any = UntouchableEngine(url())
    ids: dict[str, Any] = {"engagement_id": "e", "org_id": "o"}
    with RunningStub("insecure") as stub:
        calls = [
            lambda: engagement.seed_engagement(settings=bad, engine=engine),
            lambda: engagement.revoke_engagement(settings=bad, engine=engine, **ids),
            lambda: runner.run_check(settings=bad, engine=engine, stub=stub, **ids),
            lambda: runner.collect_report(settings=bad, engine=engine, outcome="issue", **ids),
        ]
        for call in calls:
            with pytest.raises(engagement.ConfigRefused) as caught:
                await call()
            assert caught.value.code == code
            assert PASSWORD not in str(caught.value) + repr(caught.value)
            assert caught.value.__context__ is None
        assert stub.connections_before_now() == 0


@pytest.mark.parametrize(
    "other", [url("vulnscope"), url("vulnscope_tasks_ffffffff"), url(suffix="?database=x")]
)
def test_an_engine_for_another_url_is_refused(other: str) -> None:
    with pytest.raises(engagement.ConfigRefused) as caught:
        engagement.check_config(make_settings(), UntouchableEngine(other))  # type: ignore[arg-type]
    assert caught.value.code == "engine_mismatch"


class Watched:
    """Drives ``_send_watched`` with a slow ledger and a scripted permission poll."""

    def __init__(self, *answers: bool | Exception) -> None:
        self.harness = Harness()
        self.answers = list(answers)
        real = self.harness.ledger.append

        async def slow_append(**kwargs: Any) -> Any:
            await asyncio.sleep(0.6)  # longer than two poll intervals
            entry = await real(**kwargs)
            self.harness.events.append("recorded")
            return entry

        self.harness.ledger.append = slow_append  # type: ignore[method-assign]

    async def poll(self) -> bool:
        self.harness.events.append("poll")
        answer = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
        if isinstance(answer, Exception):
            raise answer
        return answer

    async def send(self, stub: RunningStub) -> Any:
        return await runner._send_watched(
            stub=stub,
            fresh_view=self.harness.fresh_view,
            deps=self.harness.deps,
            run_id="run-1",
            still_permitted=self.poll,
        )


def test_poll_interval_is_pinned() -> None:
    assert runner.WATCH_INTERVAL_S == 0.25


async def test_watcher_never_polls_before_the_decision_is_recorded() -> None:
    watched = Watched(False)  # already revoked: an early watcher would cancel the append
    with RunningStub("stall") as stub:
        assert await watched.send(stub) is None
    events = watched.harness.events
    assert events.index("recorded") < events.index("poll")
    assert [e["payload"]["rule_id"] for e in watched.harness.ledger.entries] == ["ALLOW"]


async def test_a_denial_is_always_recorded_and_the_watcher_never_runs() -> None:
    watched = Watched(False)
    watched.harness.view_changes["status"] = "revoked"
    with RunningStub("insecure") as stub:
        decision, response = await watched.send(stub)
        assert stub.connections_before_now() == 0
    assert (decision.rule_id, response) == (RuleId.REVOKED, None)
    assert [e["payload"]["rule_id"] for e in watched.harness.ledger.entries] == ["REVOKED"]
    assert "poll" not in watched.harness.events


async def test_revoke_in_flight_cancels_the_send() -> None:
    watched = Watched(True, True, False)
    with RunningStub("stall") as stub:
        assert await asyncio.wait_for(watched.send(stub), 3.0) is None
        assert await asyncio.to_thread(stub.wait_for_client_close)
    assert watched.harness.events.count("poll") == 3


async def test_a_failing_poll_cancels_the_send_and_raises() -> None:
    watched = Watched(ConnectionError("db down"))
    with RunningStub("stall") as stub:
        with pytest.raises(ConnectionError):
            await asyncio.wait_for(watched.send(stub), 3.0)
        assert len(asyncio.all_tasks()) == 1  # neither task is left behind


async def test_a_completed_send_is_returned_and_the_watcher_stops() -> None:
    watched = Watched(True)
    with RunningStub("insecure") as stub:
        decision, response = await watched.send(stub)
    assert decision.allowed and response is not None
    polls = watched.harness.events.count("poll")
    await asyncio.sleep(0.6)
    assert watched.harness.events.count("poll") == polls
    assert len(asyncio.all_tasks()) == 1


async def test_send_failure_propagates_through_the_watcher(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport, "TOTAL_TIMEOUT_S", 0.2)
    with RunningStub("stall") as stub:
        with pytest.raises(transport.SendFailed) as caught:
            await Watched(True).send(stub)
    assert caught.value.code == "timeout"


@pytest.mark.parametrize(
    ("code", "outcome"),
    [
        ("revoked_before_send", "revoked"),
        ("window_closed_before_send", "denied"),
        ("recheck_failed", "denied"),
    ],
)
async def test_a_refused_recheck_is_an_outcome_without_a_finding(
    monkeypatch: pytest.MonkeyPatch, code: str, outcome: str
) -> None:
    async def refuse(**kwargs: Any) -> Any:
        raise transport.SendRefused(code, SimpleNamespace(ledger_seq=1))  # type: ignore[arg-type]

    monkeypatch.setattr(runner, "_send_watched", refuse)
    monkeypatch.setattr(runner, "PostgresChainBackend", lambda engine: object())
    with RunningStub("insecure") as stub:
        result = await runner.run_check(
            settings=make_settings(),
            engine=UntouchableEngine(url()),  # type: ignore[arg-type]
            engagement_id="e",
            org_id="o",
            stub=stub,
        )
    assert result == runner.RunOutcome(outcome, (1,), None, code)


async def test_other_sender_refusals_still_raise(monkeypatch: pytest.MonkeyPatch) -> None:
    async def refuse(**kwargs: Any) -> Any:
        raise transport.SendRefused("port_not_pinned", None)

    monkeypatch.setattr(runner, "_send_watched", refuse)
    monkeypatch.setattr(runner, "PostgresChainBackend", lambda engine: object())
    with RunningStub("insecure") as stub:
        with pytest.raises(transport.SendRefused):
            await runner.run_check(
                settings=make_settings(),
                engine=UntouchableEngine(url()),  # type: ignore[arg-type]
                engagement_id="e",
                org_id="o",
                stub=stub,
            )


class ReadBackend:
    def __init__(self, entries: int, count: int | None = None) -> None:
        self.entries = list(range(entries))
        self.count = entries if count is None else count
        self.limits: list[int | None] = []

    async def read(self, chain_id: str, start_seq: int = 0, limit: int | None = None) -> Any:
        self.limits.append(limit)
        for entry in self.entries[start_seq:][:limit]:
            yield entry

    async def record_count(self, chain_id: str) -> int:
        return self.count


@pytest.mark.parametrize(
    ("entries", "count", "verified", "reasons"),
    [
        (3, None, VerifyResult("ok", None, 3, None), ()),
        (4, None, VerifyResult("ok", None, 4, None), ("ledger_read_bounded",)),
        (2, 3, VerifyResult("ok", None, 3, None), ("ledger_read_short",)),
        (2, None, VerifyResult("ok", None, 3, None), ("ledger_read_short",)),
        (3, None, VerifyResult("bad_record", 1, 2, None), ("ledger_not_verified",)),
        (0, None, VerifyResult("ok", None, 0, None), ("ledger_empty",)),
    ],
    ids=["complete", "bounded", "count-differs", "verify-differs", "unverified", "empty"],
)
async def test_an_unreliable_ledger_read_is_incomplete(
    monkeypatch: pytest.MonkeyPatch,
    entries: int,
    count: int | None,
    verified: VerifyResult,
    reasons: tuple[str, ...],
) -> None:
    monkeypatch.setattr(runner, "MAX_LEDGER_ENTRIES", 3, raising=False)
    backend: Any = ReadBackend(entries, count)
    read, found = await runner._read_for_check(backend, "engagement:e", verified)
    assert found == reasons
    assert len(read) <= 3
    assert backend.limits == [4]  # never an unbounded read
