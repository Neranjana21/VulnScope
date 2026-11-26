"""api/logging.py: allowlisted structured events only (design 9, PD-10 item 3)."""
from __future__ import annotations

import json
import logging

import pytest

from vulnscope.api.logging import ALLOWED_EVENTS, ALLOWED_FIELDS, Coalescer, ScrubFilter, log_event

CANARY = "CANARY-bearer-1234"


def records(caplog: pytest.LogCaptureFixture) -> list[dict]:
    return [json.loads(r.getMessage()) for r in caplog.records if r.name == "vulnscope.api"]


def test_non_allowlisted_fields_are_dropped(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG):
        log_event("auth_failed", reason="missing", authorization=f"Bearer {CANARY}",
                  token=CANARY, headers={"a": CANARY}, dsn=f"postgresql://u:{CANARY}@h/d",
                  request_id="r1", route="/v1/x")
    (rec,) = records(caplog)
    assert set(rec) <= ALLOWED_FIELDS | {"event"}
    assert rec["event"] == "auth_failed" and rec["reason"] == "missing"
    if CANARY in json.dumps(rec) or any(CANARY in str(r.__dict__) for r in caplog.records):
        pytest.fail("leak")


def test_unknown_event_is_a_programming_error() -> None:
    with pytest.raises(ValueError):
        log_event("made_up_event")


def test_event_vocabulary() -> None:
    assert {"auth_failed", "role_denied", "cross_org_miss", "unhandled_exception",
            "app_role_check_failed", "revoke_unrecorded", "revoke_repair_failed",
            "scan_gate_error", "ledger_write_failed"} <= ALLOWED_EVENTS


def test_field_values_are_truncated_and_control_free(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG):
        log_event("cross_org_miss", route="/v1/x\n{" + "a" * 500)
    (rec,) = records(caplog)
    assert "\n" not in rec["route"] and len(rec["route"]) <= 128


def test_coalescer_limits_to_ten_per_second_and_reports_suppressed() -> None:
    t = [100.0]
    c = Coalescer(per_second=10, monotonic=lambda: t[0])
    allowed = [c.allow() for _ in range(25)]
    assert allowed.count(True) == 10
    t[0] += 1.0
    assert c.allow() is True
    assert c.take_suppressed() == 15
    assert c.take_suppressed() == 0


def test_scrub_filter_drops_exception_text_on_foreign_records() -> None:
    rec = logging.LogRecord("uvicorn.error", logging.ERROR, "f", 1, "msg %s", (CANARY,),
                            (ValueError, ValueError(CANARY), None))
    rec.exc_text = CANARY
    rec.stack_info = CANARY
    assert ScrubFilter().filter(rec) is True
    assert rec.exc_info is None and rec.exc_text is None and rec.stack_info is None
    assert rec.args == ()
