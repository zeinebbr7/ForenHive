from __future__ import annotations

import ipaddress
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from db import get_session
from models.report import AttackerProfile
from services.profiler import build_profile

router = APIRouter(prefix="/api/profiling", tags=["profiling"])


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


@router.get("/{ip}", response_model=AttackerProfile)
async def profile_live(ip: str) -> AttackerProfile:
    """Live IP profiling — builds profile on the fly from ES + enrichment + Ollama."""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid IP address")
    return await build_profile(ip)
