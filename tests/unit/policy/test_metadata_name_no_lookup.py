"""SEC-A3: a D7 hostname never triggers a DNS lookup, in every configuration."""

from __future__ import annotations

import pytest
from policy_test_support import MapResolver, run_decide

from vulnscope.policy.types import RuleId

NAMES = [
    "metadata",
    "METADATA.",
    "metadata.google.internal.",
    "x.metadata.google.internal",
    "Metadata.Google.Internal",
]
CONFIGS = [
    dict(profile="standard"),
    dict(profile="lab", lab_enabled=True),
]


@pytest.mark.parametrize("cfg", CONFIGS)
@pytest.mark.parametrize("with_allow", [True, False])
@pytest.mark.parametrize("name", NAMES)
def test_no_lookup(name: str, with_allow: bool, cfg: dict) -> None:
    resolver = MapResolver({"metadata": ("192.0.2.1",), "metadata.google.internal": ("192.0.2.1",)})
    allow = (
        ("metadata", "metadata.google.internal", "*.metadata.google.internal") if with_allow else ()
    )
    lab_enabled = cfg.get("lab_enabled", False)
    decision, _ = run_decide(
        name, allow=allow, resolver=resolver, profile=cfg["profile"], lab_enabled=lab_enabled
    )
    assert decision.rule_id == RuleId.DENY_ALWAYS_LIST
    assert resolver.calls == []
