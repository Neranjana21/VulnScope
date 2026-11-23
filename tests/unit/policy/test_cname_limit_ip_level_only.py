"""SEC-A11: documents a LIMIT. A name-level exclusion is NOT enforced across a CNAME.

The Resolver Protocol returns IPs only, so a hostname in ``scope.deny`` cannot be
matched against a CNAME target; only IP-level exclusion holds. The assertion below
records the current behaviour on purpose (no xfail); it is a visible limitation,
not a guarantee. Post-gate reports must say "CNAME into an excluded name: IP-level
only".
"""

from __future__ import annotations

from policy_test_support import run_decide


def test_name_level_exclusion_not_enforced_across_cname() -> None:
    allowed_name, excluded_name = "front.lab.test", "excluded.lab.test"
    # the CNAME chain front -> excluded is invisible to decide(): the resolver
    # only hands back the final address, which carries no name.
    d, _ = run_decide(
        allowed_name,
        allow=(allowed_name,),
        deny=(excluded_name,),
        table={allowed_name: ("192.0.2.77",)},
    )
    assert d.allowed  # LIMIT, see module docstring


def test_shared_ip_with_an_excluded_name_is_allowed() -> None:
    d, _ = run_decide(
        "a.lab.test",
        allow=("a.lab.test",),
        deny=("b.lab.test",),
        table={"a.lab.test": ("192.0.2.5",), "b.lab.test": ("192.0.2.5",)},
    )
    assert d.allowed
