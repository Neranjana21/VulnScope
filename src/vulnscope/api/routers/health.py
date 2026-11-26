"""``/healthz`` (open, no DB, no version) and the admin-only ``/metrics`` stub (N-07: no counters,
so no cross-tenant aggregate can leak)."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.responses import PlainTextResponse

from vulnscope.api.auth import Principal
from vulnscope.api.deps import ADMIN_ROLE

router = APIRouter()


@router.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/metrics")
async def metrics(principal: Principal = Depends(ADMIN_ROLE)) -> PlainTextResponse:  # noqa: B008
    return PlainTextResponse("# vulnscope metrics stub (Slice 0)\n")
