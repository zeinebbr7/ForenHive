import ipaddress
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from services.elasticsearch import get_es
from services.yara_client import get_forensic_engine

router = APIRouter(prefix="/api/forensics", tags=["forensics"])

_SHA256_RE = re.compile(r"^[A-Fa-f0-9]{64}$")


# ────────────── Timeline ──────────────

class TimelineEvent(BaseModel):
    timestamp: datetime
    honeypot: str
    source_ip: Optional[str] = None
    event_type: Optional[str] = None
    session_id: Optional[str] = None
    detail: Optional[str] = None
    severity: Optional[str] = None


class TimelineResponse(BaseModel):
    total: int
    events: List[TimelineEvent]


@router.get("/timeline", response_model=TimelineResponse)
async def timeline(
    ip: Optional[str] = Query(None),
    session_id: Optional[str] = Query(None),
    date_from: Optional[datetime] = Query(None),
    date_to: Optional[datetime] = Query(None),
    limit: int = Query(500, ge=1, le=5000),
) -> TimelineResponse:
    if not any([ip, session_id, date_from, date_to]):
        raise HTTPException(status_code=400, detail="provide at least one filter")

    es = get_es()
    filters: List[Dict[str, Any]] = []
    if ip:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            raise HTTPException(status_code=400, detail="invalid ip")
        filters.append({"term": {"source.ip": ip}})
    if session_id:
        filters.append({"term": {"session": session_id}})
    if date_from or date_to:
        rng: Dict[str, str] = {}
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
    events: List[TimelineEvent] = []
    for h in hits:
        s = h["_source"]
        ts_raw = s.get("@timestamp")
        try:
            ts = datetime.fromisoformat(str(ts_raw).replace("Z", "+00:00"))
        except Exception:
            ts = datetime.now(tz=timezone.utc)
        detail = (
            s.get("input")
            or s.get("command")
            or s.get("http.request.uri")
            or s.get("uri")
            or s.get("message")
            or s.get("event.id")
            or s.get("eventid")
        )
        # ES stores fields as flat dot-notation ("source.ip", "honeypot.type")
        events.append(
            TimelineEvent(
                timestamp=ts,
                honeypot=s.get("honeypot.type") or s.get("honeypot", "unknown"),
                source_ip=s.get("source.ip") or s.get("src_ip"),
                event_type=s.get("event.id") or s.get("eventid") or s.get("event.action"),
                session_id=s.get("session.id") or s.get("session") or s.get("session_id"),
                detail=str(detail) if detail is not None else None,
                severity=str(s.get("severity")) if s.get("severity") is not None else None,
            )
        )
    total = resp["hits"]["total"]
    total = total["value"] if isinstance(total, dict) else total
    return TimelineResponse(total=int(total), events=events)


# ────────────── YARA ──────────────

class YaraMatch(BaseModel):
    rule: str
    tags: List[str] = []
    meta: Dict[str, Any] = {}


class YaraScanResponse(BaseModel):
    sha256: str
    matches: List[YaraMatch] = []
    engine_available: bool = True


@router.get("/yara/{sha256}", response_model=YaraScanResponse)
async def yara_scan(sha256: str) -> YaraScanResponse:
    if not _SHA256_RE.match(sha256):
        raise HTTPException(status_code=400, detail="invalid sha256")
    data = await get_forensic_engine().scan_sha256(sha256.lower())
    matches = [
        YaraMatch(
            rule=m.get("rule", "unknown"),
            tags=m.get("tags", []),
            meta=m.get("meta", {}),
        )
        for m in data.get("matches", [])
    ]
    return YaraScanResponse(
        sha256=sha256.lower(),
        matches=matches,
        engine_available=data.get("engine_available", True),
    )


@router.get("/yara")
async def yara_dionaea_scan(limit: int = Query(50, ge=1, le=500)):
    return {"results": await get_forensic_engine().scan_all_dionaea(limit=limit)}
