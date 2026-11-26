"""Ledger verification flow (design 7.3, 13; PD-15, PD-25). Owner resolution happens BEFORE any
ledger call; ``checkpoint`` in any form is refused (a client never names a server-side path)."""
from __future__ import annotations

import asyncio
from typing import Any

from fastapi import Request

from vulnscope.api.auth import Principal
from vulnscope.api.db import db_read
from vulnscope.api.deps import cross_org_miss
from vulnscope.api.limits import MAX_CHAIN_PARAM_LEN
from vulnscope.api.problem import Detail, ProblemError
from vulnscope.api.scoping import not_found, resolve_chain_owner_org
from vulnscope.api.state import AppState
from vulnscope.errors import ReasonCode
from vulnscope.models.schemas.ledger import VerifyResponse

LIMITATION = "no-checkpoint; tail truncation cannot be detected"


def _unavailable() -> ProblemError:
    return ProblemError(503, ReasonCode.UNAVAILABLE, Detail.UNAVAILABLE,
                        headers={"Retry-After": "2"})


async def verify_owned_chain(state: AppState, org_id: str, chain_id: str
                             ) -> tuple[dict[str, Any], bool]:
    """Verify ``chain_id`` (ownership already established). Returns (body, no_checkpoint)."""
    t = state.timeouts
    permit = state.gates.verify.try_acquire(org_id)
    try:
        async with asyncio.timeout(t.verify_deadline_s):
            head = await state.chain_backend.head(chain_id)
            if head is not None and head.seq + 1 > t.verify_max_records:
                raise _unavailable()
            checkpoint = await state.checkpoint_source.latest_valid(chain_id)
            result = await state.verify_fn(chain_id, state.chain_backend, checkpoint)
    except TimeoutError:
        raise _unavailable() from None
    finally:
        permit.release()
    body = VerifyResponse(result=result.result, first_bad_seq=result.first_bad_seq,
                          records=result.records,
                          checkpoint_seq=result.checkpoint_seq).model_dump(mode="json")
    return body, result.checkpoint_seq is None


async def verify_request(request: Request, state: AppState, principal: Principal
                         ) -> tuple[dict[str, Any], bool]:
    q = request.query_params
    if "checkpoint" in q.keys():  # noqa: SIM118 - QueryParams.keys() includes valueless keys
        raise ProblemError(422, ReasonCode.INVALID_REQUEST, Detail.BAD_REQUEST)
    chains = q.getlist("chain")
    if len(chains) != 1:
        raise ProblemError(422, ReasonCode.INVALID_REQUEST, Detail.BAD_REQUEST)
    chain = chains[0]
    if len(chain) > MAX_CHAIN_PARAM_LEN:
        cross_org_miss(request)
        not_found()
    async with db_read(state) as s:
        owner = await resolve_chain_owner_org(s, chain)
    if owner is None or owner != principal.org_id:
        cross_org_miss(request)
        not_found()
    return await verify_owned_chain(state, principal.org_id, chain)
