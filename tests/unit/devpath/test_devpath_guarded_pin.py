"""``guarded_head`` must send through the pin, for BOTH targets.

The real action is kept, so ``action_mismatch`` cannot be what stops the send. Only the
other decision fields the pin checks are forged, and the pin's own code is asserted. The
socket factory is a tripwire, so a sender that skipped the pin could not connect either.
"""

from __future__ import annotations

import asyncio
import dataclasses
from collections.abc import Iterator
from typing import Any

import lab_fake  # noqa: F401 - the port 3000 safety net, also when this file runs alone
import pytest
from devpath import targets, transport
from devpath.stub import RunningStub
from test_devpath_lab_target import no_network
from test_devpath_transport import Harness

from vulnscope.policy.types import PolicyDecision, RuleId

# name -> (forged fields, the pin's own refusal code)
FORGERIES: dict[str, tuple[dict[str, Any], str]] = {
    # Truthy but not True: it passes the early deny return and must stop at the pin.
    "allowed-not-true": ({"allowed": 1}, "not_an_allow"),
    "rule-deny": ({"rule_id": RuleId.OUT_OF_SCOPE}, "not_an_allow"),
    "rule-text": ({"rule_id": "ALLOW"}, "not_an_allow"),
    "not-recorded": ({"ledger_seq": None}, "not_recorded"),
    "ips-empty": ({"resolved_ips": ()}, "address_not_pinned"),
    "ips-other": ({"resolved_ips": ("127.0.0.2",)}, "address_not_pinned"),
    "ips-v6": ({"resolved_ips": ("::1",)}, "address_not_pinned"),
    "ips-metadata": ({"resolved_ips": ("169.254.169.254",)}, "address_not_pinned"),
    "ips-extra": ({"resolved_ips": ("127.0.0.1", "127.0.0.2")}, "address_not_pinned"),
}


@pytest.fixture(params=["juice", "stub"])
def target(request: pytest.FixtureRequest) -> Iterator[Any]:
    if request.param == "juice":
        yield targets.JUICE_SHOP
        return
    with RunningStub("insecure") as running:
        yield running


@pytest.mark.parametrize("forgery", FORGERIES)
async def test_guarded_head_applies_the_pin(
    target: Any, forgery: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    changes, code = FORGERIES[forgery]
    real = transport.decide_and_record
    actions: list[tuple[Any, Any]] = []

    async def fake(action: Any, *args: Any, **kwargs: Any) -> PolicyDecision:
        decision = await real(action, *args, **kwargs)
        assert decision.allowed is True and decision.rule_id is RuleId.ALLOW
        forged = dataclasses.replace(decision, **changes)
        actions.append((action, forged.action))
        return forged

    monkeypatch.setattr(transport, "decide_and_record", fake)
    harness = Harness()
    sending = asyncio.Event()
    with no_network(monkeypatch):
        with pytest.raises(transport.SendRefused) as caught:
            await transport.guarded_head(
                stub=target,
                fresh_view=harness.fresh_view,
                deps=harness.deps,
                run_id="run-1",
                sending=sending,
            )
    assert caught.value.code == code
    assert not sending.is_set()
    [(asked, returned)] = actions
    assert returned is asked
    assert harness.events == ["view", "head", "append", "view"]  # past the re-check
