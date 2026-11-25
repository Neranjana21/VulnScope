"""Engagement routes. No route declares a body, a Pydantic model or a query parameter: the body is
read by ``bodies.read_json`` only after authentication and the role check."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response

from vulnscope.api.auth import Principal
from vulnscope.api.bodies import read_json
from vulnscope.api.db import db_read
from vulnscope.api.deps import ANY_ROLE, WRITE_ROLE, get_state
from vulnscope.api.engagement_flow import create_engagement
from vulnscope.api.limits import BODY_CAP_REVOKE
from vulnscope.api.responses import json_response, missing_logged
from vulnscope.api.revoke_recorder import revoke_engagement
from vulnscope.api.scoping import get_engagement
from vulnscope.api.validation import validate_revoke_request
from vulnscope.models.schemas.engagement import EngagementRevokeResponse
from vulnscope.models.schemas.views import EngagementView

router = APIRouter()


@router.post("/v1/engagements")
async def post_engagement(request: Request,
                          principal: Principal = Depends(WRITE_ROLE)) -> Response:  # noqa: B008
    return await create_engagement(request, get_state(request), principal)


@router.get("/v1/engagements/{id}")
async def read_engagement(id: str, request: Request,
                          principal: Principal = Depends(ANY_ROLE)) -> Response:  # noqa: B008
    state = get_state(request)
    async with db_read(state) as s:
        snap = await missing_logged(request, get_engagement(s, id, principal.org_id))
    view = EngagementView.model_validate({
        "id": snap.id, "schema_version": 1, "name": snap.name, "profile": snap.profile,
        "status": snap.status, "targets": dict(snap.targets), "scope": dict(snap.scope),
        "authorization": dict(snap.authorization),
        "identities": [
            {"label": i.get("label"), "role": i.get("role"),
             "auth": {"type": (i.get("auth") or {}).get("type")}}  # never secret_ref
            for i in snap.identities],
        "ownership_rules": list(snap.ownership_rules), "asset_tags": list(snap.asset_tags),
        "created_at": snap.created_at, "revoked_at": snap.revoked_at,
        "revoked_reason": snap.revoked_reason})
    return json_response(view.model_dump(mode="json"))


@router.post("/v1/engagements/{id}/revoke")
async def revoke(id: str, request: Request,
                 principal: Principal = Depends(WRITE_ROLE)) -> Response:  # noqa: B008
    state = get_state(request)
    reason = validate_revoke_request(await read_json(request, BODY_CAP_REVOKE))
    revoked_at, seq = await missing_logged(
        request, revoke_engagement(state, principal, id, reason))
    body = EngagementRevokeResponse(status="revoked", revoked_at=revoked_at, ledger_seq=seq)
    return json_response(body.model_dump(mode="json"))
