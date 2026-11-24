"""validation.map_validation_errors: pydantic errors -> contract codes (design 7.1, 8)."""
from __future__ import annotations

import copy
from typing import Any

import pytest
from api_payloads import valid_payload
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from vulnscope.api.validation import map_validation_errors
from vulnscope.models.schemas.engagement import EngagementCreateRequest


def _errors(payload: dict[str, Any]):
    with pytest.raises(ValidationError) as ei:
        EngagementCreateRequest.model_validate(payload)
    return map_validation_errors(ei.value)


def test_unknown_field_at_root_records_parent_path_and_count_only() -> None:
    p = valid_payload()
    p["foo_canary"] = 1
    m = _errors(p)
    assert m.codes == ["UNKNOWN_FIELD"] and m.paths == ["$"] and m.unknown_field_count == 1
    assert "foo_canary" not in repr(m)


def test_unknown_field_nested_path() -> None:
    p = valid_payload()
    p["scope"]["foo_canary"] = 1
    m = _errors(p)
    assert m.codes == ["UNKNOWN_FIELD"] and m.paths == ["scope"]


def test_naive_datetime() -> None:
    p = valid_payload()
    p["scope"]["window"]["not_before"] = "2026-01-01T00:00:00"
    m = _errors(p)
    assert m.codes == ["WINDOW_NAIVE_DATETIME"]
    assert m.paths == ["scope.window.not_before"]


def test_window_missing_whole_and_partial() -> None:
    p = valid_payload()
    del p["scope"]["window"]
    assert _errors(p).codes == ["WINDOW_MISSING"]
    q = valid_payload()
    del q["scope"]["window"]["not_after"]
    assert _errors(q).codes == ["WINDOW_MISSING"]


def test_secret_ref_pattern() -> None:
    p = valid_payload()
    p["identities"] = [{"label": "a", "role": "r",
                        "auth": {"type": "bearer", "secret_ref": "ref://A/b"}}]
    m = _errors(p)
    assert m.codes == ["SECRET_INLINE"] and m.paths == ["identities.*.auth.secret_ref"]


def test_precedence_order() -> None:
    p = valid_payload()
    p["foo"] = 1
    p["scope"]["window"]["not_before"] = "2026-01-01T00:00:00"
    p["identities"] = [{"label": "a", "role": "r",
                        "auth": {"type": "bearer", "secret_ref": "BAD"}}]
    assert _errors(p).codes == ["UNKNOWN_FIELD", "WINDOW_NAIVE_DATETIME", "SECRET_INLINE"]


def test_non_contract_errors_map_to_nothing() -> None:
    p = valid_payload()
    p["name"] = 12
    assert _errors(p).codes == []


@settings(max_examples=60, deadline=None)
@given(st.lists(st.text(min_size=1, max_size=30), min_size=1, max_size=40, unique=True))
def test_attacker_chosen_names_never_reach_the_mapping(names: list[str]) -> None:
    p = copy.deepcopy(valid_payload())
    known = set(p) | set(p["scope"])
    names = [n for n in names if n not in known]
    if not names:
        return
    for i, n in enumerate(names):
        (p if i % 2 == 0 else p["scope"])[n] = 1
    m = _errors(p)
    assert m.codes == ["UNKNOWN_FIELD"]
    assert m.unknown_field_count == len(names)
    blob = repr(m)
    for n in names:
        if len(n) > 3:
            assert n not in blob
    assert set(m.paths) <= {"$", "scope"}


def test_error_flood_is_bounded() -> None:
    p = valid_payload()
    for i in range(5000):
        p[f"x{i}"] = 1
    m = _errors(p)
    assert m.codes == ["UNKNOWN_FIELD"] and m.unknown_field_count <= 64
