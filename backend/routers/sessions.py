"""
sessions.py — Sessions d'attaque agrégées
Rôle : liste et détail des sessions d'attaque (groupement par IP/session_id).
URL    : /api/sessions/*
Deps   : Elasticsearch (honeypot-logs-*).
Auth   : Bearer token (forenhive.token) requis (sauf chat public).
Codes  : 200 OK | 401 non auth | 403 interdit | 404 absent | 422 valid | 500 engine.
"""

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response
from models.session import SessionDetail, SessionListResponse, SessionSummary
from services.elasticsearch import get_es

router = APIRouter(prefix="/api/sessions", tags=["sessions"])


@router.get("", response_model=SessionListResponse)
async def list_sessions(
    limit: int = Query(100, ge=1, le=500),
    active_only: bool = Query(False),
) -> SessionListResponse:
    rows = await get_es().sessions(limit=limit, active_only=active_only)

    # Enrich with the forensic engine's per-session risk_score (stored in
    # PostgreSQL forensic_sessions). The ES aggregation has no score, so without
    # this every session would surface as 0 in the UI.
    sids = [r.get("session_id") for r in rows if r.get("session_id")]
    if sids:
        try:
            from db import session_scope
            from sqlalchemy import text

            async with session_scope() as db:
                res = await db.execute(
                    text(
                        "SELECT session_id, risk_score FROM forensic_sessions WHERE session_id = ANY(:sids)"
                    ),
                    {"sids": sids},
                )
                score_by_sid = {row["session_id"]: row["risk_score"] for row in res.mappings()}
            for r in rows:
                score = score_by_sid.get(r.get("session_id"))
                if score is not None:
                    r["risk_score"] = int(score)
                    r["risk_level"] = (
                        "CRITICAL"
                        if score >= 80
                        else "HIGH"
                        if score >= 60
                        else "MEDIUM"
                        if score >= 40
                        else "LOW"
                        if score >= 20
                        else "INFO"
                    )
        except Exception:
            pass

    items = [
        SessionSummary(**{k: v for k, v in r.items() if k in SessionSummary.model_fields})
        for r in rows
    ]
    active = sum(1 for r in rows if r.get("status") == "active")
    return SessionListResponse(total=len(items), active=active, items=items)


@router.get("/{session_id}", response_model=SessionDetail)
async def get_session(session_id: str) -> SessionDetail:
    detail = await get_es().session_detail(session_id)
    if not detail:
        raise HTTPException(status_code=404, detail="session not found")
    return SessionDetail.model_validate(detail)


@router.delete("/{session_id}", status_code=204, response_class=Response)
async def force_close_session(session_id: str) -> Response:
    ok = await get_es().mark_session_closed(session_id)
    if not ok:
        raise HTTPException(status_code=404, detail="session not found or already closed")
    return Response(status_code=204)
