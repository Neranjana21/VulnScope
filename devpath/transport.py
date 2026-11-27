"""STEP 1 DEVELOPMENT PATH: no gateway, no worker, not the security boundary.

``guarded_head`` is the only way to send: fresh engagement view, then
``decide_and_record``, then a second fresh read of status and window, then one HEAD of
``/`` to one of two in-code targets on 127.0.0.1: our own stub, or the sealed
``devpath.targets.JUICE_SHOP`` (ADR-0014). One decision, one request. The scope guard decides; the
re-check and the pin checks here can only refuse, never allow (the pin is needed because the
policy does not restrict ports, ADR-0013). A revoke or expiry after the second read and
before the bytes are on the wire is not prevented here.

Cancellation seam: to stop an in-flight request (revoke watcher), run ``guarded_head``
as a task and cancel it. The socket is closed and ``CancelledError`` propagates.

Redirects are never followed, ``Location`` is never read, and only the NAMES of the
five allowlisted headers leave this module (values are replaced with ``b""``).
"""

from __future__ import annotations

import asyncio
import socket
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

import h11

from devpath.stub import NotTheRealStub, RunningStub, bound_port
from devpath.targets import JUICE_SHOP, JUICE_SHOP_PORT, LabTarget
from vulnscope.ledger.chain import ChainBackend
from vulnscope.policy.clock import Clock
from vulnscope.policy.decide_and_record import decide_and_record
from vulnscope.policy.ratelimit import RateLimitStore
from vulnscope.policy.resolver import ResolutionError
from vulnscope.policy.target import TargetParseError, canonical_target
from vulnscope.policy.types import Action, EngagementPolicyView, PolicyDecision, RuleId
from vulnscope.validate.types import HEADER_NAMES, HeaderResponse

PINNED_HOST = "127.0.0.1"
ADAPTER_PREFIX = "devpath.security_headers@1|job="
TOTAL_TIMEOUT_S = 5.0  # connect, send and receive together
RECHECK_TIMEOUT_S = 2.0  # the pre-send re-read; running out of time refuses
RECHECK_CODES = ("revoked_before_send", "window_closed_before_send", "recheck_failed")
MAX_HEADER_BYTES = 16 * 1024
_KEPT_NAMES = frozenset(name.encode("ascii") for name in HEADER_NAMES)


@dataclass(frozen=True)
class TransportDeps:
    clock: Clock
    rate_limit_store: RateLimitStore
    chain_backend: ChainBackend
    actor: str = "system"
    lab_enabled: bool = False
    lab_cidr: str | None = None


class SendRefused(Exception):
    """The sender refused before creating a socket. ``code`` is from a closed set."""

    def __init__(self, code: str, decision: PolicyDecision | None) -> None:
        super().__init__(code)
        self.code = code
        self.decision = decision


class SendFailed(Exception):
    """An allowed send failed. ``code`` is fixed text and never contains target bytes."""

    def __init__(self, code: str, decision: PolicyDecision) -> None:
        super().__init__(code)
        self.code = code
        self.decision = decision


class _WireError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class _RefusingResolver:
    """Step 1 performs no DNS. IP literals never reach a resolver."""

    def resolve(self, hostname: str) -> tuple[str, ...]:
        raise ResolutionError("Step 1 performs no DNS")


def _stub_port(stub: object, decision: PolicyDecision | None) -> int:
    try:
        return bound_port(stub)
    except NotTheRealStub:
        raise SendRefused("not_the_real_stub", decision) from None
    except (OSError, RuntimeError):
        raise SendRefused("stub_not_running", decision) from None


def _target_port(target: object, decision: PolicyDecision | None) -> int:
    """The allowlist (ADR-0014): the object ``JUICE_SHOP`` itself (identity only), or an
    exact running stub asked for its socket's port. Everything else is refused."""
    if target is JUICE_SHOP:
        return JUICE_SHOP_PORT
    return _stub_port(target, decision)


def _origin(port: int) -> str:
    return f"http://{PINNED_HOST}:{port}/"


def _refusal(decision: PolicyDecision, pinned_port: int) -> str | None:
    """Why this decision must not be sent, or None. Can only refuse."""
    if decision.allowed is not True or decision.rule_id is not RuleId.ALLOW:
        return "not_an_allow"
    if decision.ledger_seq is None:
        return "not_recorded"
    if decision.action.is_redirect_hop:
        return "redirect_hop"
    try:
        target = canonical_target(decision.action.target)
    except TargetParseError:
        return "target_unparseable"
    if target.scheme != "http":
        return "scheme_not_pinned"
    if target.host != PINNED_HOST:
        return "host_not_pinned"
    if target.port != pinned_port:
        return "port_not_pinned"
    if decision.resolved_ips != (PINNED_HOST,):
        return "address_not_pinned"
    if decision.action.kind != "http":
        return "kind_not_pinned"
    # The parser canonicalises (127.1 becomes 127.0.0.1), so the text must match too.
    if decision.action.target != _origin(pinned_port):
        return "target_not_exact"
    return None


async def _recheck(
    fresh_view: Callable[[], Awaitable[EngagementPolicyView]], clock: Clock
) -> str | None:
    """Why the send must not start now, or None. Can only refuse; any failure refuses."""
    try:
        async with asyncio.timeout(RECHECK_TIMEOUT_S):
            view = await fresh_view()
        if view.status != "active":
            return "revoked_before_send"
        # The clock is read after the view, so a slow read cannot hide an expiry.
        if not view.window_not_before <= clock.now() <= view.window_not_after:
            return "window_closed_before_send"
    except Exception:  # noqa: BLE001 - fail closed; the error text is never kept
        return "recheck_failed"
    return None


def _new_socket() -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setblocking(False)
    return sock


async def _exchange(sock: socket.socket, ip: str, port: int) -> HeaderResponse:
    loop = asyncio.get_running_loop()
    await loop.sock_connect(sock, (ip, port))  # numeric address: no lookup
    conn = h11.Connection(h11.CLIENT, max_incomplete_event_size=MAX_HEADER_BYTES)
    request = h11.Request(
        method="HEAD", target="/", headers=[("Host", f"{ip}:{port}"), ("Connection", "close")]
    )
    wire = (conn.send(request) or b"") + (conn.send(h11.EndOfMessage()) or b"")
    await loop.sock_sendall(sock, wire)
    received = 0
    while True:
        event = conn.next_event()
        if event is h11.NEED_DATA:
            data = await loop.sock_recv(sock, min(4096, MAX_HEADER_BYTES + 1 - received))
            received += len(data)
            if received > MAX_HEADER_BYTES:
                raise _WireError("headers_too_large")
            conn.receive_data(data)
        elif isinstance(event, h11.Response):
            return HeaderResponse(
                status=event.status_code,
                headers=tuple((bytes(n), b"") for n, _ in event.headers if n in _KEPT_NAMES),
            )
        elif not isinstance(event, h11.InformationalResponse):
            raise _WireError("protocol_error")


async def _send(ip: str, port: int, decision: PolicyDecision) -> HeaderResponse:
    sock = _new_socket()
    try:
        async with asyncio.timeout(TOTAL_TIMEOUT_S):
            return await _exchange(sock, ip, port)
    except TimeoutError:  # must precede OSError, its base class
        code = "timeout"
    except _WireError as exc:
        code = exc.code
    except h11.ProtocolError:
        code = "protocol_error"
    except OSError:
        code = "connection_error"
    finally:
        sock.close()
    # Raised outside the handlers so no exception context can carry target bytes.
    raise SendFailed(code, decision)


async def _pinned_send(
    target: object, decision: PolicyDecision, sending: asyncio.Event | None
) -> HeaderResponse:
    """The last gate before a socket: allowlisted target, then the pin. No await comes
    between these checks and the creation of the socket."""
    port = _target_port(target, decision)
    refused = _refusal(decision, port)
    if refused is not None:
        raise SendRefused(refused, decision)
    if sending is not None:
        sending.set()  # signal only: the decision is recorded and the send starts now
    return await _send(PINNED_HOST, port, decision)


async def guarded_head(
    *,
    stub: RunningStub | LabTarget,
    fresh_view: Callable[[], Awaitable[EngagementPolicyView]],
    deps: TransportDeps,
    run_id: str,
    sending: asyncio.Event | None = None,
) -> tuple[PolicyDecision, HeaderResponse | None]:
    """Decide, record, then HEAD the target. There is no URL, host or port argument.
    ``stub`` (the name predates ADR-0014) must be an exact ``devpath.stub.RunningStub``
    or the object ``devpath.targets.JUICE_SHOP``.

    A deny returns ``(decision, None)`` with nothing sent. Any error from the first view
    read or the ledger propagates before a socket exists. ``SendRefused``: an allow failed
    the pin, or the pre-send re-check refused it (a code in ``RECHECK_CODES``).
    ``SendFailed``: the allowed request timed out or the response was unusable.
    """
    action = Action(
        kind="http",
        target=_origin(_target_port(stub, None)),
        adapter=ADAPTER_PREFIX + run_id,
    )
    view = await fresh_view()  # re-read immediately before the decision (rule 4)
    decision = await decide_and_record(
        action,
        view,
        deps.clock.now(),
        resolver=_RefusingResolver(),
        clock=deps.clock,
        rate_limit_store=deps.rate_limit_store,
        chain_backend=deps.chain_backend,
        actor=deps.actor,
        lab_enabled=deps.lab_enabled,
        lab_cidr=deps.lab_cidr,
    )
    if not decision.allowed:
        return decision, None
    if decision.action != action:
        raise SendRefused("action_mismatch", decision)
    # The last await before the socket: everything below it is synchronous until connect.
    withdrawn = await _recheck(fresh_view, deps.clock)
    if withdrawn is not None:
        raise SendRefused(withdrawn, decision)
    return decision, await _pinned_send(stub, decision, sending)
