from __future__ import annotations

import ipaddress
<<<<<<< HEAD
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
=======
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
>>>>>>> zinoba

from db import get_session
from models.report import AttackerProfile
from services.elasticsearch import get_es
from services.profiler import build_profile

router = APIRouter(prefix="/api/profiling", tags=["profiling"])


<<<<<<< HEAD
def _severity(score: int | None) -> str:
    s = score or 0
    if s >= 70:
        return "CRITICAL"
    if s >= 40:
        return "HIGH"
    if s >= 20:
        return "MEDIUM"
    return "LOW"


def _row_to_summary(row: Any) -> Dict[str, Any]:
    profile = row.profile or {}
    return {
        "id": row.id,
        "source_ip": row.source_ip,
        "risk_score": row.risk_score or 0,
        "severity": _severity(row.risk_score),
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "actor_type": profile.get("actor_type") or profile.get("dominant_tactic"),
        "sophistication": profile.get("sophistication"),
        "confidence": profile.get("confidence"),
        "country": (profile.get("geographic_profile") or {}).get("country")
        or profile.get("country"),
        "recommended_action": profile.get("recommended_action"),
    }


# NOTE: static paths must be declared BEFORE the dynamic `/{ip}` route,
# otherwise FastAPI matches them as IP strings.


@router.get("")
@router.get("/")
async def list_profiles(
    severity: str | None = None,
    limit: int = 100,
    session: AsyncSession = Depends(get_session),
) -> List[Dict[str, Any]]:
    limit = max(1, min(int(limit), 500))
    rows = (
        await session.execute(
            text(
                "SELECT id, source_ip, profile, risk_score, created_at "
                "FROM suspect_profiles ORDER BY risk_score DESC NULLS LAST, created_at DESC "
                "LIMIT :lim"
            ),
            {"lim": limit},
        )
    ).all()
    out = [_row_to_summary(r) for r in rows]
    if severity:
        sev = severity.upper()
        out = [p for p in out if p["severity"] == sev]
    return out


@router.get("/stats/summary")
async def stats_summary(session: AsyncSession = Depends(get_session)) -> Dict[str, Any]:
    row = (
        await session.execute(
            text(
                """
                SELECT
                  COUNT(*)                                        AS total,
                  COUNT(*) FILTER (WHERE risk_score >= 70)        AS critical,
                  COUNT(*) FILTER (WHERE risk_score BETWEEN 40 AND 69) AS high,
                  COUNT(*) FILTER (WHERE risk_score BETWEEN 20 AND 39) AS medium,
                  COUNT(*) FILTER (WHERE risk_score < 20)         AS low,
                  COALESCE(ROUND(AVG(risk_score))::int, 0)        AS avg_score
                FROM suspect_profiles
                """
            )
        )
    ).one()
    return {
        "total": row.total,
        "critical": row.critical,
        "high": row.high,
        "medium": row.medium,
        "low": row.low,
        "avg_score": row.avg_score,
    }


@router.get("/by-id/{profile_id}")
async def profile_by_id(
    profile_id: int, session: AsyncSession = Depends(get_session)
) -> Dict[str, Any]:
    row = (
        await session.execute(
            text(
                "SELECT id, source_ip, profile, risk_score, created_at "
                "FROM suspect_profiles WHERE id = :id"
            ),
            {"id": profile_id},
        )
    ).first()
    if not row:
        raise HTTPException(status_code=404, detail="profile not found")
    return {
        "id": row.id,
        "source_ip": row.source_ip,
        "risk_score": row.risk_score or 0,
        "severity": _severity(row.risk_score),
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "profile": row.profile or {},
    }
=======
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
    """Severity-band counts + average risk across the top attackers."""
    rows = await get_es().top_attackers(limit=200)
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    total = len(rows)
    score_sum = 0.0
    for r in rows:
        sev = r.get("severity", "LOW")
        if sev in counts:
            counts[sev] += 1
        score_sum += float(r.get("risk_score") or 0)
    return {
        "total": total,
        "critical": counts["CRITICAL"],
        "high": counts["HIGH"],
        "medium": counts["MEDIUM"],
        "low": counts["LOW"],
        "avg_score": round(score_sum / total, 1) if total else 0,
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
>>>>>>> zinoba


@router.get("/{ip}", response_model=AttackerProfile)
async def profile_live(ip: str) -> AttackerProfile:
    """Live IP profiling — builds profile on the fly from ES + enrichment + Ollama."""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid IP address")
    return await build_profile(ip)
