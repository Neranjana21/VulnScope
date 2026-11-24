"""``GET /v1/ledger/verify``: counts only. The query string is read manually after authentication;
``checkpoint`` in any form is refused (a client never names a server-side path)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response

from vulnscope.api.auth import Principal
from vulnscope.api.deps import ANY_ROLE, get_state
from vulnscope.api.ledger_flow import LIMITATION, verify_request
from vulnscope.api.responses import json_response

router = APIRouter()


@router.get("/v1/ledger/verify")
async def verify(request: Request,
                 principal: Principal = Depends(ANY_ROLE)) -> Response:  # noqa: B008
    body, no_checkpoint = await verify_request(request, get_state(request), principal)
    headers = {"X-Ledger-Limitation": LIMITATION} if no_checkpoint else None
    return json_response(body, headers=headers)
