"""SEC-A12: scheme and port rows; non-http(s) hops reject."""

from __future__ import annotations

import pytest
from policy_test_support import run_decide

from vulnscope.policy.target import canonical_target
from vulnscope.policy.types import RuleId


def test_http_and_https_same_host_distinct_scheme_and_port() -> None:
    a, b = canonical_target("http://h.test"), canonical_target("https://h.test")
    assert a.host == b.host == "h.test"
    assert (a.scheme, a.port) == ("http", 80)
    assert (b.scheme, b.port) == ("https", 443)


@pytest.mark.parametrize(
    "raw", ["ftp://h.test", "file://h.test", "gopher://h.test", "//h.test", "http:h.test"]
)
def test_non_http_hop_rejects_as_out_of_scope(raw: str) -> None:
    decision, resolver = run_decide(
        raw, allow=("h.test",), table={"h.test": ("192.0.2.1",)}, redirect=True
    )
    assert not decision.allowed
    assert decision.rule_id == RuleId.OUT_OF_SCOPE
    assert decision.reason.startswith("UNPARSEABLE_TARGET:")
    assert resolver.calls == []
    assert raw not in decision.reason


def test_port_is_parsed_but_not_policy_matched() -> None:
    decision, _ = run_decide("h.test:8443", allow=("h.test",), table={"h.test": ("192.0.2.1",)})
    assert decision.allowed
