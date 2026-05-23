"""
forensics.py — Pilotage du Forensic Engine
Rôle : déclenchement manuel d'une analyse forensique, statut du dernier run.
URL    : /api/forensics/*
Deps   : services.forensic_runner (subprocess docker exec).
Auth   : Bearer token (forenhive.token) requis (sauf chat public).
Codes  : 200 OK | 401 non auth | 403 interdit | 404 absent | 422 valid | 500 engine.
"""

import ipaddress
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query
from pydantic import BaseModel
from services.elasticsearch import get_es
from services.forensic_runner import last_forensic_run, run_forensic_engine

router = APIRouter(prefix="/api/forensics", tags=["forensics"])


# ────────────── Timeline ──────────────


class TimelineEvent(BaseModel):
    timestamp: datetime
    honeypot: str
    source_ip: str | None = None
    event_type: str | None = None
    session_id: str | None = None
    detail: str | None = None
    severity: str | None = None


class TimelineResponse(BaseModel):
    total: int
    events: list[TimelineEvent]


@router.get("/timeline", response_model=TimelineResponse)
async def timeline(
    ip: str | None = Query(None),
    session_id: str | None = Query(None),
    date_from: datetime | None = Query(None),
    date_to: datetime | None = Query(None),
    limit: int = Query(500, ge=1, le=5000),
) -> TimelineResponse:
    if not any([ip, session_id, date_from, date_to]):
        raise HTTPException(status_code=400, detail="provide at least one filter")

    es = get_es()
    filters: list[dict[str, Any]] = []
    if ip:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            raise HTTPException(status_code=400, detail="invalid ip")
        filters.append({"term": {"source.ip": ip}})
    if session_id:
        filters.append({"term": {"session": session_id}})
    if date_from or date_to:
        rng: dict[str, str] = {}
        if date_from:
            rng["gte"] = date_from.isoformat()
        if date_to:
            rng["lte"] = date_to.isoformat()
        filters.append({"range": {"@timestamp": rng}})

    body = {
        "size": limit,
        "query": {"bool": {"filter": filters}},
        "sort": [{"@timestamp": {"order": "asc"}}],
    }
    resp = await es.client.search(
        index=es.settings.honeypot_indices,
        body=body,
        ignore_unavailable=True,
        allow_no_indices=True,
    )
    hits = resp["hits"]["hits"]
    events: list[TimelineEvent] = []
    for h in hits:
        s = h["_source"]
        ts_raw = s.get("@timestamp")
        try:
            ts = datetime.fromisoformat(str(ts_raw).replace("Z", "+00:00"))
        except Exception:
            ts = datetime.now(tz=UTC)
        honeypot_raw = s.get("honeypot", "unknown")
        honeypot_str = (
            honeypot_raw.get("type") if isinstance(honeypot_raw, dict) else honeypot_raw
        ) or "unknown"
        session_raw = s.get("session") or s.get("session_id")
        session_str = (
            session_raw.get("id") if isinstance(session_raw, dict) else session_raw
        ) or None
        detail = (
            s.get("input")
            or s.get("command")
            or s.get("message")
            or (s.get("url") or {}).get("path")
            or s.get("eventid")
            or (s.get("event") or {}).get("id")
        )
        events.append(
            TimelineEvent(
                timestamp=ts,
                honeypot=honeypot_str,
                source_ip=(s.get("source") or {}).get("ip") or s.get("src_ip"),
                event_type=s.get("eventid") or (s.get("event") or {}).get("id"),
                session_id=session_str,
                detail=str(detail) if detail is not None else None,
                severity=str(s.get("severity")) if s.get("severity") is not None else None,
            )
        )
    total = resp["hits"]["total"]
    total = total["value"] if isinstance(total, dict) else total
    return TimelineResponse(total=int(total), events=events)


@router.post("/run")
async def trigger_engine_run(background_tasks: BackgroundTasks):
    """Trigger an immediate forensic engine run (non-blocking)."""
    if last_forensic_run["status"] == "running":
        raise HTTPException(status_code=409, detail="Analysis already in progress")
    background_tasks.add_task(run_forensic_engine)
    return {
        "status": "queued",
        "message": "Forensic analysis queued. Check /api/forensics/status for progress.",
        "queued_at": datetime.now(tz=UTC).isoformat(),
    }


@router.get("/status")
async def forensic_run_status():
    """Status of the last/current forensic engine run."""
    return {
        "status": last_forensic_run["status"],
        "timestamp": last_forensic_run["timestamp"],
        "error": last_forensic_run.get("error", ""),
    }
