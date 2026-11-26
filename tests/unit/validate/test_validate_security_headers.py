"""The five-header presence check and its redacted evidence (ADR-0013, round 25)."""

from __future__ import annotations

import hashlib

import pytest
from hypothesis import given
from hypothesis import strategies as st

from vulnscope.validate.evidence import build_evidence
from vulnscope.validate.security_headers import evaluate
from vulnscope.validate.types import HEADER_NAMES, CheckResult, HeaderResponse

CANARY = "canary-7f3a9c"
ALL = tuple((name.encode(), b"x") for name in HEADER_NAMES)


def _all_with(verdict: str) -> tuple[tuple[str, str], ...]:
    return tuple((name, verdict) for name in HEADER_NAMES)


def test_exactly_the_five_names() -> None:
    assert HEADER_NAMES == (
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
    )


def test_all_present_is_no_issue() -> None:
    result = evaluate(HeaderResponse(200, ALL))
    assert result == CheckResult("no_issue", _all_with("present"), None)  # type: ignore[arg-type]


def test_all_absent_is_an_issue() -> None:
    result = evaluate(HeaderResponse(204, ()))
    assert result == CheckResult("issue", _all_with("absent"), None)  # type: ignore[arg-type]


@pytest.mark.parametrize("missing", HEADER_NAMES)
def test_each_header_alone_missing_is_an_issue(missing: str) -> None:
    headers = tuple(h for h in ALL if h[0] != missing.encode())
    result = evaluate(HeaderResponse(200, headers))
    assert result.outcome == "issue"
    assert dict(result.verdicts) == {
        name: "absent" if name == missing else "present" for name in HEADER_NAMES
    }


@pytest.mark.parametrize("value", [b"", b"garbage", b"unsafe-inline *", b"\xff\x00"])
def test_values_are_never_judged(value: bytes) -> None:
    headers = tuple((name.encode(), value) for name in HEADER_NAMES)
    assert evaluate(HeaderResponse(200, headers)).outcome == "no_issue"


def test_names_match_case_insensitively_and_duplicates_count_once() -> None:
    headers = tuple((name.upper().encode(), b"") for name in HEADER_NAMES) + ALL
    assert evaluate(HeaderResponse(200, headers)).verdicts == _all_with("present")


def test_frame_ancestors_does_not_count_as_x_frame_options() -> None:
    headers = tuple(h for h in ALL if h[0] != b"x-frame-options")
    headers += ((b"content-security-policy", b"frame-ancestors 'none'"),)
    assert dict(evaluate(HeaderResponse(200, headers)).verdicts)["x-frame-options"] == "absent"


@pytest.mark.parametrize("name", [b"x-frame-options ", b"x_frame_options", b"x-frame-option"])
def test_lookalike_names_do_not_count(name: bytes) -> None:
    result = evaluate(HeaderResponse(200, ((name, b"DENY"),)))
    assert dict(result.verdicts)["x-frame-options"] == "absent"


@pytest.mark.parametrize("status", [300, 301, 302, 303, 307, 308, 399])
def test_3xx_is_inconclusive_redirect_not_followed(status: int) -> None:
    result = evaluate(HeaderResponse(status, ((b"location", CANARY.encode()),)))
    assert result == CheckResult("inconclusive", (), "redirect_not_followed")


@pytest.mark.parametrize("status", [0, 100, 199, 400, 401, 404, 500, 503, 999, -1])
def test_other_status_is_inconclusive(status: int) -> None:
    assert evaluate(HeaderResponse(status, ())) == CheckResult(
        "inconclusive", (), "unexpected_status"
    )


def test_excerpt_is_the_fixed_lines_and_hash_covers_its_bytes() -> None:
    evidence = build_evidence(evaluate(HeaderResponse(200, ((b"referrer-policy", b"x"),))))
    assert evidence.excerpt == (
        "content-security-policy: absent\n"
        "x-frame-options: absent\n"
        "x-content-type-options: absent\n"
        "referrer-policy: present\n"
        "permissions-policy: absent"
    )
    assert evidence.content_sha256 == hashlib.sha256(evidence.excerpt.encode()).hexdigest()


@pytest.mark.parametrize("reason", ["redirect_not_followed", "unexpected_status"])
def test_inconclusive_excerpt(reason: str) -> None:
    evidence = build_evidence(CheckResult("inconclusive", (), reason))  # type: ignore[arg-type]
    assert evidence.excerpt == f"inconclusive: {reason}"


class _Sneaky(str):
    """Equal to an allowed word but formats as target text."""

    def __str__(self) -> str:
        return CANARY

    def __format__(self, spec: str) -> str:
        return CANARY


def _five(first: tuple[str, str]) -> tuple[tuple[str, str], ...]:
    return (first, *_all_with("absent")[1:])


@pytest.mark.parametrize(
    ("outcome", "verdicts", "reason"),
    [
        ("issue", _five((CANARY, "absent")), None),
        ("issue", _five(("content-security-policy", CANARY)), None),
        ("issue", _five(("content-security-policy", "weak")), None),
        ("issue", _all_with("absent")[:4], None),
        ("issue", (*_all_with("absent"), (CANARY, "present")), None),
        ("issue", _all_with("present"), None),
        ("no_issue", _all_with("absent"), None),
        ("issue", _all_with("absent"), CANARY),
        ("inconclusive", (), CANARY),
        ("inconclusive", (), None),
        ("inconclusive", _all_with("absent"), "unexpected_status"),
        (CANARY, _all_with("absent"), None),
    ],
)
def test_build_evidence_rejects_anything_outside_the_closed_vocabulary(
    outcome: str, verdicts: tuple[tuple[str, str], ...], reason: str | None
) -> None:
    with pytest.raises(ValueError) as caught:
        build_evidence(CheckResult(outcome, verdicts, reason))  # type: ignore[arg-type]
    assert str(caught.value) == "check result is outside the closed vocabulary"
    assert caught.value.__context__ is None


def test_build_evidence_writes_its_own_constants_not_the_inputs() -> None:
    verdicts = tuple((_Sneaky(n), _Sneaky(v)) for n, v in _all_with("absent"))
    evidence = build_evidence(CheckResult("issue", verdicts, None))  # type: ignore[arg-type]
    assert CANARY not in evidence.excerpt
    inconclusive = CheckResult("inconclusive", (), _Sneaky("unexpected_status"))  # type: ignore[arg-type]
    assert CANARY not in build_evidence(inconclusive).excerpt


_NAMES = st.one_of(st.binary(max_size=64), st.sampled_from([n.encode() for n in HEADER_NAMES]))


@given(
    st.integers(min_value=-(2**40), max_value=2**40) | st.integers(200, 299),
    st.lists(st.tuples(_NAMES, st.binary(max_size=64)), max_size=20),
)
def test_evaluate_is_total_and_no_target_bytes_reach_evidence(
    status: int, headers: list[tuple[bytes, bytes]]
) -> None:
    marker = CANARY.encode()
    planted = tuple((n, marker + v) for n, v in headers) + ((marker, marker),)
    result = evaluate(HeaderResponse(status, planted))
    evidence = build_evidence(result)
    assert CANARY not in repr(result) + repr(evidence)
    # Values make no difference at all.
    blank = evaluate(HeaderResponse(status, tuple((n, b"") for n, _ in planted)))
    assert (blank, build_evidence(blank)) == (result, evidence)
