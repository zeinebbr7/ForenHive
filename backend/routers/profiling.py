import ipaddress
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import text

from db import get_sessionmaker
from models.report import AttackerProfile
from services.elasticsearch import get_es
from services.profiler import build_profile

router = APIRouter(prefix="/api/profiling", tags=["profiling"])


@router.get("", response_model=List[Dict[str, Any]])
async def list_profiles(limit: int = Query(50, ge=1, le=200)) -> List[Dict[str, Any]]:
    """List top attacker IPs with summary stats (lightweight per-row profile).

    Backed by an ES aggregation over honeypot indices. Each row carries the
    fields the dashboard needs for the profile list: source_ip, event_count,
    honeypots, country, risk_score, severity, first/last seen.
    """
    rows = await get_es().top_attackers(limit=limit)
    # Synthesize a stable id (ip-based) so the frontend can route by row.
    for i, r in enumerate(rows):
        r["id"] = i + 1
    return rows


@router.get("/stats/summary")
async def stats_summary() -> Dict[str, Any]:
    """Severity-band counts + average risk from PostgreSQL forensic_sessions."""
    async with get_sessionmaker()() as db:
        result = await db.execute(
            text(
                """
                SELECT
                    COUNT(*)                                        AS total,
                    COUNT(*) FILTER (WHERE risk_score >= 80)       AS critical,
                    COUNT(*) FILTER (WHERE risk_score >= 60
                                      AND risk_score <  80)        AS high,
                    COUNT(*) FILTER (WHERE risk_score >= 40
                                      AND risk_score <  60)        AS medium,
                    COUNT(*) FILTER (WHERE risk_score <  40
                                      OR  risk_score IS NULL)      AS low,
                    COALESCE(ROUND(AVG(risk_score)::numeric, 1), 0) AS avg_score
                FROM forensic_sessions
                """
            )
        )
        row = result.mappings().one()

    return {
        "total":     int(row["total"]),
        "critical":  int(row["critical"]),
        "high":      int(row["high"]),
        "medium":    int(row["medium"]),
        "low":       int(row["low"]),
        "avg_score": float(row["avg_score"]),
    }


@router.get("/by-id/{row_id}", response_model=AttackerProfile)
async def profile_by_id(row_id: int) -> AttackerProfile:
    """Resolve the row position from list_profiles to a full profile by IP.

    No persistent profile table exists — we re-aggregate the same top-N list
    and resolve the ip at the requested position. Stable for a given dataset.
    """
    rows = await get_es().top_attackers(limit=200)
    if row_id < 1 or row_id > len(rows):
        raise HTTPException(status_code=404, detail="profile row not found")
    ip = rows[row_id - 1].get("source_ip")
    if not ip:
        raise HTTPException(status_code=404, detail="profile row missing ip")
    return await build_profile(ip)


@router.get("/{ip}", response_model=AttackerProfile)
async def profile(ip: str) -> AttackerProfile:
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid IP address")
    return await build_profile(ip)
