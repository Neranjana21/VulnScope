"""policy/engagement_check.py: pure string-level engagement validation (design 11.4)."""

from __future__ import annotations

import dataclasses
import socket
from collections.abc import Sequence

import pytest
from target_corpus import METADATA_ENCODINGS, REJECT

from vulnscope.policy.engagement_check import ScopeIssue, validate_engagement_targets

OPEN = ("0.0.0.0/0", "::/0")


def check(
    domains: Sequence[str] = (),
    ip_ranges: Sequence[str] = (),
    allow: Sequence[str] = (),
    deny: Sequence[str] = (),
    expected: Sequence[str] = (),
    profile: str = "standard",
    lab_enabled: bool = False,
    lab_cidr: str | None = None,
) -> tuple[ScopeIssue, ...]:
    return validate_engagement_targets(
        domains=domains,
        ip_ranges=ip_ranges,
        allow=allow,
        deny=deny,
        expected_ip_ranges=expected,
        profile=profile,
        lab_enabled=lab_enabled,
        lab_cidr=lab_cidr,  # type: ignore[arg-type]
    )


def brief(issues: tuple[ScopeIssue, ...]) -> list[tuple]:
    return [(i.field, i.index, i.verdict, i.rule, i.code) for i in issues]


def test_clean_engagement_has_no_issues() -> None:
    assert (
        check(
            ["a.lab.test", "192.0.2.5"],
            ["203.0.113.0/24"],
            ["a.lab.test", "192.0.2.0/24", "203.0.113.0/24"],
        )
        == ()
    )


def test_not_covered() -> None:
    assert brief(check(["b.lab.test"], [], ["a.lab.test"])) == [
        ("targets.domains", 0, "not_in_scope", "NOT_COVERED", "HOST")
    ]
    assert brief(check([], ["198.51.100.0/24"], ["203.0.113.0/24"]))[0][2:4] == (
        "not_in_scope",
        "NOT_COVERED",
    )


@pytest.mark.parametrize("raw", METADATA_ENCODINGS)
def test_every_metadata_encoding_denied_even_with_open_allow(raw: str) -> None:
    (issue,) = check([raw], [], OPEN)
    assert (issue.verdict, issue.rule) == ("denied", "ALWAYS_DENY")


@pytest.mark.parametrize(("raw", "code"), REJECT)
def test_every_parser_reject_is_invalid(raw: str, code: str) -> None:
    (issue,) = check([raw], [], OPEN)
    assert (issue.verdict, issue.rule) == ("invalid", "SYNTAX")
    assert issue.code == f"PARSE:{code}"


def test_pd13_target_ranges_denied_by_overlap() -> None:
    ranges = [
        "169.0.0.0/8",
        "0.0.0.0/0",
        "::/0",
        "fd00:ec2::/32",
        "169.254.0.0/16",
        "::ffff:169.254.0.0/112",
        "64:ff9b::/96",
        "2002::/16",
        "2001::/32",
        "100.64.0.0/10",
        "224.0.0.0/3",
        "0.0.0.0/7",
    ]
    issues = check([], ranges, OPEN)
    assert len(issues) == len(ranges)
    for i, issue in enumerate(issues):
        assert (issue.field, issue.index, issue.verdict, issue.rule, issue.code) == (
            "targets.ip_ranges",
            i,
            "denied",
            "ALWAYS_DENY",
            "RANGE_OVERLAP",
        ), ranges[i]


def test_allow_entry_wholly_inside_always_deny_is_flagged() -> None:
    issues = check(["169.254.169.254"], [], ["169.254.169.254"])
    assert brief(issues) == [
        ("scope.allow", 0, "denied", "ALWAYS_DENY", "ALLOW_ENTRY_DENIED"),
        ("targets.domains", 0, "denied", "ALWAYS_DENY", "HOST"),
    ]
    for entry in (
        "169.254.0.0/16",
        "metadata",
        "*.metadata.google.internal",
        "instance-data",
        "fe80::/10",
        "2001::/32",
    ):
        (issue,) = check([], [], [entry])
        assert (issue.field, issue.verdict, issue.code) == (
            "scope.allow",
            "denied",
            "ALLOW_ENTRY_DENIED",
        )


def test_allow_overlapping_partly_is_accepted_but_target_denied() -> None:
    assert check([], [], ["100.64.0.0/10", "fc00::/7", "0.0.0.0/0"]) == ()
    (issue,) = check(["100.100.100.200"], [], ["100.64.0.0/10"])
    assert (issue.field, issue.verdict, issue.rule) == ("targets.domains", "denied", "ALWAYS_DENY")


def test_metadata_name_target() -> None:
    (issue,) = check(["metadata"], [], ["lab.test"])
    assert (issue.verdict, issue.rule) == ("denied", "ALWAYS_DENY")
    (issue,) = check(["x.instance-data.ec2.internal"], [], ["*.ec2.internal"])
    assert (issue.verdict, issue.rule) == ("denied", "ALWAYS_DENY")


def test_private_literal_with_and_without_opt_in() -> None:
    assert check(["10.1.2.3"], [], ["10.0.0.0/8"]) == ()
    (issue,) = check(["10.1.2.3"], [], ["0.0.0.0/0"])
    assert (issue.rule, issue.code) == ("PRIVATE_RANGE", "NO_OPT_IN")
    (issue,) = check(["127.0.0.1"], [], ["127.0.0.1", "0.0.0.0/0"])
    assert (issue.rule, issue.code) == ("PRIVATE_RANGE", "LOOPBACK")


def test_private_range_target_rules() -> None:
    assert check([], ["10.1.0.0/16"], ["10.0.0.0/8"]) == ()
    (issue,) = check([], ["10.1.0.0/16"], ["0.0.0.0/0"])
    assert (issue.rule, issue.code) == ("PRIVATE_RANGE", "NO_OPT_IN")
    (issue,) = check([], ["127.0.0.0/24"], ["127.0.0.0/8"])
    assert (issue.rule, issue.code) == ("PRIVATE_RANGE", "LOOPBACK")
    (issue,) = check([], ["10.0.0.0/7"], ["10.0.0.0/8"])  # straddles a block: conservative
    assert issue.verdict == "denied"


def test_lab_profile_rules() -> None:
    assert check(["127.0.0.1"], [], ["127.0.0.1"], profile="lab", lab_enabled=True) == ()
    assert (
        check(
            ["10.20.1.1"],
            [],
            ["10.20.0.0/16"],
            profile="lab",
            lab_enabled=True,
            lab_cidr="10.20.0.0/16",
        )
        == ()
    )
    (issue,) = check(
        ["10.30.1.1"],
        [],
        ["10.30.0.0/16"],
        profile="lab",
        lab_enabled=True,
        lab_cidr="10.20.0.0/16",
    )
    assert (issue.rule, issue.code) == ("LAB", "OUTSIDE_LAB")
    (issue,) = check(
        [],
        ["10.30.0.0/24"],
        ["10.30.0.0/16"],
        profile="lab",
        lab_enabled=True,
        lab_cidr="10.20.0.0/16",
    )
    assert (issue.rule, issue.code) == ("LAB", "OUTSIDE_LAB")
    (issue,) = check(["127.0.0.1"], [], ["127.0.0.1"], profile="lab", lab_enabled=False)
    assert (issue.field, issue.index, issue.verdict, issue.rule, issue.code) == (
        "profile",
        -1,
        "denied",
        "LAB",
        "PROFILE_NOT_ENABLED",
    )
    (issue,) = check([], [], [], profile="standard", lab_enabled=True, lab_cidr="garbage")
    assert (issue.field, issue.index, issue.verdict, issue.rule, issue.code) == (
        "profile",
        -1,
        "invalid",
        "LAB",
        "LAB_CONFIG",
    )
    assert check([], [], [], profile="standard", lab_enabled=False, lab_cidr="garbage") == ()


def test_scope_deny_partial_overlap_on_a_range() -> None:
    (issue,) = check([], ["10.0.0.0/24"], ["10.0.0.0/8"], deny=["10.0.0.128/25"])
    assert (issue.rule, issue.code) == ("SCOPE_DENY", "RANGE_OVERLAP")
    (issue,) = check(["10.1.2.3"], [], ["10.0.0.0/8"], deny=["::ffff:10.1.0.0/112"])
    assert (issue.rule, issue.code) == ("SCOPE_DENY", "HOST")
    (issue,) = check(["a.lab.test"], [], ["*.lab.test"], deny=["a.lab.test"])
    assert issue.rule == "SCOPE_DENY"


def test_union_coverage_public_and_conservative_private() -> None:
    assert check([], ["203.0.113.0/24"], ["203.0.113.0/25", "203.0.113.128/25"]) == ()
    (issue,) = check([], ["10.0.0.0/24"], ["10.0.0.0/25", "10.0.0.128/25"])
    assert (issue.rule, issue.code) == ("PRIVATE_RANGE", "NO_OPT_IN")


def test_mapped_spellings_are_equivalent() -> None:
    forms = ["::ffff:10.1.0.0/112", "::ffff:a01:0/112", "10.1.0.0/16"]
    results = [brief(check(["10.1.2.3"], [], ["10.0.0.0/8"], deny=[f])) for f in forms]
    assert results[0] == results[1] == results[2] != []


def test_scope_syntax_issues_short_circuit_targets() -> None:
    issues = check(
        ["a.test", "b.test"], [], ["*", "a.test"], deny=["bad entry"], expected=["lab.test"]
    )
    assert [(i.field, i.index, i.verdict, i.rule) for i in issues] == [
        ("scope.allow", 0, "invalid", "SYNTAX"),
        ("scope.deny", 0, "invalid", "SYNTAX"),
        ("scope.expected_ip_ranges", 0, "invalid", "SYNTAX"),
    ]
    assert all(i.code.startswith("ENTRY:") for i in issues)
    assert issues[2].code == "ENTRY:expected_not_network"


def test_limit() -> None:
    (issue,) = check(["a.test"], [], [f"h{i}.test" for i in range(257)])
    assert (issue.field, issue.index, issue.verdict, issue.rule, issue.code) == (
        "scope.allow",
        -1,
        "invalid",
        "LIMIT",
        "TOO_MANY",
    )


def test_deterministic_order_and_one_issue_per_entry() -> None:
    issues = check(["x.test", "metadata", "y.test"], ["198.51.100.0/24"], ["a.test"], profile="lab")
    fields = [i.field for i in issues]
    assert fields == [
        "profile",
        "targets.domains",
        "targets.domains",
        "targets.domains",
        "targets.ip_ranges",
    ]
    assert [i.index for i in issues if i.field == "targets.domains"] == [0, 1, 2]


def test_type_errors_for_programming_mistakes() -> None:
    with pytest.raises(TypeError):
        check([5], [], [])  # type: ignore[list-item]
    with pytest.raises(TypeError):
        check(["a.test"], [], [], profile="prod")
    with pytest.raises(TypeError):
        validate_engagement_targets(
            domains="a.test",
            ip_ranges=(),
            allow=(),
            deny=(),  # type: ignore[arg-type]
            expected_ip_ranges=(),
            profile="standard",
        )


def test_hostile_text_never_raises_and_never_echoes() -> None:
    canary = "CANARY-9f3a"
    hostile = [
        canary + "\x00\ud800",
        canary + "@x",
        canary * 400,
        "http://" + canary + "/8",
        canary + "‮",
        "*." + canary,
        canary + "/33",
    ]
    issues = check(hostile, hostile, hostile, hostile, hostile)
    assert issues
    for issue in issues:
        assert canary not in repr(issue)
        assert all(canary not in str(getattr(issue, f.name)) for f in dataclasses.fields(issue))
    issues = check(hostile, hostile, ["*"], [], [])
    assert all(canary not in repr(i) for i in issues)
    issues = check(hostile, hostile, OPEN, [], [])
    assert issues and all(canary not in repr(i) for i in issues)


def test_no_network_even_if_sockets_are_sabotaged(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*a: object, **k: object) -> None:
        raise AssertionError("network touched")

    monkeypatch.setattr(socket, "getaddrinfo", boom)
    monkeypatch.setattr(socket, "gethostbyname", boom)
    monkeypatch.setattr(socket, "socket", boom)
    assert check(["a.lab.test", "192.0.2.1"], ["203.0.113.0/24"], (*OPEN, "a.lab.test")) == ()


def test_issues_are_frozen_and_closed_vocabulary() -> None:
    (issue,) = check(["b.test"], [], ["a.test"])
    with pytest.raises(dataclasses.FrozenInstanceError):
        issue.index = 5  # type: ignore[misc]
    assert issue.verdict in {"denied", "not_in_scope", "invalid"}
    assert issue.rule in {
        "ALWAYS_DENY",
        "SCOPE_DENY",
        "PRIVATE_RANGE",
        "LAB",
        "NOT_COVERED",
        "SYNTAX",
        "LIMIT",
    }
