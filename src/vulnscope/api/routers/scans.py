"""Scan routes (S0: creation, view, and the findings/paths/report stubs)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response

from vulnscope.api.auth import Principal
from vulnscope.api.db import db_read
from vulnscope.api.deps import ANY_ROLE, WRITE_ROLE, get_state
from vulnscope.api.ledger_flow import LIMITATION, verify_owned_chain
from vulnscope.api.problem import ProblemError
from vulnscope.api.responses import json_response, missing_logged
from vulnscope.api.scan_flow import create_scan
from vulnscope.api.scoping import get_engagement, get_scan, not_found
from vulnscope.models.schemas.views import (
    FindingsEnvelope,
    PathsEnvelope,
    ReportStub,
    ScanStatusView,
)

router = APIRouter()


@router.post("/v1/engagements/{id}/scans", status_code=202)
async def post_scan(id: str, request: Request,
                    principal: Principal = Depends(WRITE_ROLE)) -> Response:  # noqa: B008
    return await create_scan(request, get_state(request), principal, id)


async def _scan_view(request: Request, principal: Principal, scan_id: str) -> ScanStatusView:
    state = get_state(request)
    async with db_read(state) as s:
        rec = await missing_logged(request, get_scan(s, scan_id, principal.org_id))
    return ScanStatusView.model_validate({
        "id": rec.id, "schema_version": 1, "engagement_id": rec.engagement_id,
        "status": rec.status, "stages": rec.stages, "options": rec.options,
        "schedule": rec.schedule})


@router.get("/v1/scans/{id}")
async def read_scan(id: str, request: Request,
                    principal: Principal = Depends(ANY_ROLE)) -> Response:  # noqa: B008
    view = await _scan_view(request, principal, id)
    return json_response(view.model_dump(mode="json"))


@router.get("/v1/scans/{id}/findings")
async def read_findings(id: str, request: Request,
                        principal: Principal = Depends(ANY_ROLE)) -> Response:  # noqa: B008
    await _scan_view(request, principal, id)
    return json_response(FindingsEnvelope().model_dump(mode="json"))


@router.get("/v1/scans/{id}/paths")
async def read_paths(id: str, request: Request,
                     principal: Principal = Depends(ANY_ROLE)) -> Response:  # noqa: B008
    await _scan_view(request, principal, id)
    return json_response(PathsEnvelope().model_dump(mode="json"))


@router.get("/v1/scans/{id}/report")
async def read_report(id: str, request: Request,
                      principal: Principal = Depends(ANY_ROLE)) -> Response:  # noqa: B008
    state = get_state(request)
    view = await _scan_view(request, principal, id)
    if request.query_params.getlist("format") not in ([], ["json"]):
        not_found()  # html, pdf and anything else are not implemented in S0 (OQ-5)
    async with db_read(state) as s:
        snap = await get_engagement(s, view.engagement_id, principal.org_id)
    try:
        verification, no_checkpoint = await verify_owned_chain(
            state, principal.org_id, f"engagement:{snap.id}")
        if no_checkpoint:
            verification["limitation"] = LIMITATION
    except ProblemError:
        verification = {"result": "unavailable"}
    scope = snap.scope
    stub = ReportStub(
        scan_id=view.id, engagement_id=snap.id, status=view.status,
        note="scan did not execute: no workers in this slice",
        scope={"profile": snap.profile, "allow": list(scope.get("allow", [])),
               "deny": list(scope.get("deny", [])), "window": dict(scope.get("window", {})),
               "hosting": "not verified"},
        findings=[], paths=[], ledger_verification=verification)
    return json_response(stub.model_dump(mode="json"))
