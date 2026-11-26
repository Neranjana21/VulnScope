"""DE-03/DE-04: AuthGate sizing comes from typed, validated, bounded env settings; invalid values
stop startup (fail closed) and never leak the offending value into the error text."""
from __future__ import annotations

from dataclasses import replace

import pytest

from vulnscope.api.limits import Timeouts
from vulnscope.config import AdmissionConfigError, load_admission_overrides


def load(env: dict[str, str]) -> Timeouts:
    """The same composition the lifespan performs (main.py), with an injected environment."""
    base = Timeouts()
    adm = load_admission_overrides({
        "auth_inflight": base.auth_inflight, "auth_reserved": base.auth_reserved,
        "auth_queue_wait_s": base.auth_queue_wait_s,
        "auth_db_budget_s": base.auth_db_budget_s}, env)
    return replace(
        base, auth_inflight=adm.auth_inflight, auth_reserved=adm.auth_reserved,
        auth_queue_wait_s=adm.auth_queue_wait_s, auth_db_budget_s=adm.auth_db_budget_s)


def test_no_env_gives_the_dataclass_defaults() -> None:
    assert load({}) == Timeouts()


def test_unrelated_and_unprefixed_variables_are_ignored() -> None:
    env = {"PATH": "/usr/bin", "AUTH_INFLIGHT": "3", "VULNSCOPE_DATABASE_URL": "x",
           "VULNSCOPE_API_UNKNOWN": "1"}
    assert load(env) == Timeouts()


def test_valid_overrides_apply_and_touch_nothing_else() -> None:
    t = load({
        "VULNSCOPE_API_AUTH_INFLIGHT": "8", "VULNSCOPE_API_AUTH_RESERVED": "3",
        "VULNSCOPE_API_AUTH_QUEUE_WAIT_S": "2.5", "VULNSCOPE_API_AUTH_DB_BUDGET_S": "4"})
    d = Timeouts()
    assert (t.auth_inflight, t.auth_reserved, t.auth_queue_wait_s, t.auth_db_budget_s) == (
        8, 3, 2.5, 4.0)
    assert t.request_deadline_s == d.request_deadline_s and t.claim_wait_s == d.claim_wait_s
    assert t.scan_inflight_global == d.scan_inflight_global


@pytest.mark.parametrize("name,value", [
    ("AUTH_INFLIGHT", "0"), ("AUTH_INFLIGHT", "-1"), ("AUTH_INFLIGHT", "13"),
    ("AUTH_INFLIGHT", "abc"), ("AUTH_INFLIGHT", "2.5"), ("AUTH_INFLIGHT", ""),
    ("AUTH_RESERVED", "0"), ("AUTH_RESERVED", "5"), ("AUTH_RESERVED", "-2"),
    ("AUTH_QUEUE_WAIT_S", "0"), ("AUTH_QUEUE_WAIT_S", "0.01"), ("AUTH_QUEUE_WAIT_S", "16"),
    ("AUTH_QUEUE_WAIT_S", "nan"), ("AUTH_QUEUE_WAIT_S", "inf"), ("AUTH_QUEUE_WAIT_S", "-1"),
    ("AUTH_DB_BUDGET_S", "0"), ("AUTH_DB_BUDGET_S", "0.1"), ("AUTH_DB_BUDGET_S", "11"),
    ("AUTH_DB_BUDGET_S", "nan"), ("AUTH_DB_BUDGET_S", "inf"),
])
def test_out_of_bounds_values_are_rejected(name: str, value: str) -> None:
    with pytest.raises(AdmissionConfigError):
        load({f"VULNSCOPE_API_{name}": value})


def test_combined_slots_must_fit_the_pool() -> None:
    with pytest.raises(AdmissionConfigError):
        load({"VULNSCOPE_API_AUTH_INFLIGHT": "12", "VULNSCOPE_API_AUTH_RESERVED": "4"})
    load({"VULNSCOPE_API_AUTH_INFLIGHT": "10", "VULNSCOPE_API_AUTH_RESERVED": "4"})


def test_bounds_inclusive_edges_accepted() -> None:
    t = load({
        "VULNSCOPE_API_AUTH_INFLIGHT": "1", "VULNSCOPE_API_AUTH_RESERVED": "1",
        "VULNSCOPE_API_AUTH_QUEUE_WAIT_S": "15", "VULNSCOPE_API_AUTH_DB_BUDGET_S": "10"})
    assert (t.auth_inflight, t.auth_reserved) == (1, 1)


def test_error_text_never_echoes_the_offending_value() -> None:
    secret_looking = "s3cr3t-value-xyz"
    with pytest.raises(AdmissionConfigError) as ei:
        load({"VULNSCOPE_API_AUTH_INFLIGHT": secret_looking})
    assert secret_looking not in str(ei.value) and secret_looking not in repr(ei.value)
    assert "auth_inflight" in str(ei.value)
    assert ei.value.__cause__ is None and ei.value.__suppress_context__
