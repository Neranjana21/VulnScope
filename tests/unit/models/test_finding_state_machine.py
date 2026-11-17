"""Hypothesis over every ``(current, target)`` string pair from the
Finding status vocabulary; asserts ``can_transition`` matches
``TRANSITIONS`` exactly, including that every omitted pair is ``False``.
docs/gates/slice0-plan.md Section 5, Task 0 / AC5.
"""
from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from vulnscope.models.finding_state import TRANSITIONS, can_transition

# Every status named in docs/io-contracts.md's "Finding" status-transitions
# table, plus the TRANSITIONS table's own keys/values -- the full
# vocabulary, not just TRANSITIONS' keys (so "omitted pair" coverage
# actually includes statuses that never appear as a *source*, e.g. none
# here, but this stays correct even if the vocabulary grows asymmetrically).
STATUS_VOCABULARY = sorted(
    {*TRANSITIONS.keys(), *{status for targets in TRANSITIONS.values() for status in targets}}
)


def test_status_vocabulary_matches_io_contracts() -> None:
    assert STATUS_VOCABULARY == sorted(
        {
            "candidate",
            "likely",
            "confirmed",
            "false_positive",
            "inconclusive",
            "blocked_by_policy",
            "remediated",
        }
    )


@given(current=st.sampled_from(STATUS_VOCABULARY), target=st.sampled_from(STATUS_VOCABULARY))
def test_can_transition_matches_table_exactly(current: str, target: str) -> None:
    expected = target in TRANSITIONS.get(current, frozenset())
    assert can_transition(current, target) is expected


def test_every_table_entry_is_reachable() -> None:
    for current, targets in TRANSITIONS.items():
        for target in targets:
            assert can_transition(current, target) is True


def test_unknown_source_status_has_no_transitions() -> None:
    assert can_transition("not_a_real_status", "candidate") is False


@given(target=st.sampled_from(STATUS_VOCABULARY))
def test_self_transition_never_allowed(target: str) -> None:
    # Every row in docs/io-contracts.md's table names only *other*
    # statuses as valid targets -- a status never transitions to itself.
    assert can_transition(target, target) is False
