from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from models.session import SessionDetail, SessionListResponse, SessionSummary
from services.elasticsearch import get_es

router = APIRouter(prefix="/api/sessions", tags=["sessions"])


@router.get("", response_model=SessionListResponse)
async def list_sessions(
    limit: int = Query(100, ge=1, le=500),
    active_only: bool = Query(False),
) -> SessionListResponse:
    rows = await get_es().sessions(limit=limit, active_only=active_only)
    items = [SessionSummary(**{k: v for k, v in r.items() if k in SessionSummary.model_fields}) for r in rows]
    active = sum(1 for r in rows if r.get("status") == "active")
    return SessionListResponse(total=len(items), active=active, items=items)


@router.get("/{session_id}", response_model=SessionDetail)
async def get_session(session_id: str) -> SessionDetail:
    detail = await get_es().session_detail(session_id)
    if not detail:
        raise HTTPException(status_code=404, detail="session not found")
    return SessionDetail.model_validate(detail)


@router.delete("/{session_id}", status_code=204)
async def force_close_session(session_id: str) -> None:
    ok = await get_es().mark_session_closed(session_id)
    if not ok:
        raise HTTPException(status_code=404, detail="session not found or already closed")
    return None
