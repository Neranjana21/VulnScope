"""Window edges, +/- 1 microsecond, and view-construction guards."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from policy_test_support import WINDOW_END, WINDOW_START, make_view, run_decide

from vulnscope.policy.types import RuleId

H = "a.lab.test"
TABLE = {H: ("192.0.2.1",)}
US = timedelta(microseconds=1)


@pytest.mark.parametrize(
    ("now", "rule"),
    [
        (WINDOW_START - US, RuleId.NOT_YET_VALID),
        (WINDOW_START, RuleId.ALLOW),
        (WINDOW_START + US, RuleId.ALLOW),
        (WINDOW_END - US, RuleId.ALLOW),
        (WINDOW_END, RuleId.ALLOW),
        (WINDOW_END + US, RuleId.EXPIRED),
    ],
)
def test_edges(now: datetime, rule: RuleId) -> None:
    d, _ = run_decide(H, allow=(H,), table=TABLE, now=now)
    assert d.rule_id == rule


def test_dst_like_offset_edges() -> None:
    for hours in (-8, -7, 1, 2, 14):
        tz = timezone(timedelta(hours=hours))
        d, _ = run_decide(H, allow=(H,), table=TABLE, now=WINDOW_END.astimezone(tz))
        assert d.allowed
        d, _ = run_decide(H, allow=(H,), table=TABLE, now=(WINDOW_END + US).astimezone(tz))
        assert d.rule_id == RuleId.EXPIRED


def test_naive_now_raises() -> None:
    with pytest.raises(ValueError):
        run_decide(H, allow=(H,), table=TABLE, now=datetime(2026, 1, 15))


def test_naive_view_window_raises() -> None:
    with pytest.raises(ValueError):
        make_view(window_not_before=datetime(2026, 1, 1))
    with pytest.raises(ValueError):
        make_view(window_not_after=datetime(2026, 2, 1))


def test_window_must_be_ordered() -> None:
    with pytest.raises(ValueError):
        make_view(window_not_after=WINDOW_START)
    with pytest.raises(ValueError):
        make_view(window_not_after=WINDOW_START - US)
