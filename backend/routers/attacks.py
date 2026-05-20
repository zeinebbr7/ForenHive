import asyncio
import json
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from sse_starlette.sse import EventSourceResponse

from models.attack import (
    AttackEvent,
    AttackFilter,
    AttackListResponse,
    HoneypotType,
    HourlyBucket,
    LiveStats,
    Severity,
)
from services.elasticsearch import get_es

router = APIRouter(prefix="/api/attacks", tags=["attacks"])


@router.get("", response_model=AttackListResponse)
async def list_attacks(
    ip: Optional[str] = Query(None),
    country: Optional[str] = Query(None, min_length=2, max_length=2),
    severity: Optional[Severity] = Query(None),
    honeypot: Optional[HoneypotType] = Query(None),
    date_from: Optional[datetime] = Query(None),
    date_to: Optional[datetime] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
) -> AttackListResponse:
    f = AttackFilter(
        ip=ip,
        country=country,
        severity=severity,
        honeypot=honeypot,
        date_from=date_from,
        date_to=date_to,
        page=page,
        page_size=page_size,
    )
    total, items = await get_es().search_attacks(f)
    return AttackListResponse(total=total, page=page, page_size=page_size, items=items)


@router.get("/stats/hourly", response_model=list[HourlyBucket])
async def stats_hourly(hours: int = Query(24, ge=1, le=168)) -> list[HourlyBucket]:
    buckets = await get_es().hourly_breakdown(hours=hours)
    return [HourlyBucket(**b) for b in buckets]


@router.get("/stats/top-ips")
async def stats_top_ips(limit: int = Query(10, ge=1, le=100)):
    return {"items": await get_es().top_source_ips(limit=limit)}


@router.get("/stats/top-ports")
async def stats_top_ports(limit: int = Query(10, ge=1, le=100)):
    return {"items": await get_es().top_dest_ports(limit=limit)}


@router.get("/stats/live")
async def stats_live(window: int = Query(60, ge=5, le=3600)):
    """Server-Sent Events stream of live event counts in the trailing window."""

    async def event_stream():
        es = get_es()
        try:
            while True:
                count = await es.count_last_seconds(window)
                payload = LiveStats(
                    window_seconds=window,
                    count=count,
                    events_per_second=round(count / max(window, 1), 3),
                    timestamp=datetime.now(timezone.utc),
                )
                yield {
                    "event": "tick",
                    "data": payload.model_dump_json(),
                }
                await asyncio.sleep(5)
        except asyncio.CancelledError:  # client disconnect
            return

    return EventSourceResponse(event_stream())


@router.get("/{event_id}", response_model=AttackEvent)
async def get_attack(event_id: str) -> AttackEvent:
    evt = await get_es().get_attack(event_id)
    if not evt:
        raise HTTPException(status_code=404, detail="attack event not found")
    return evt
