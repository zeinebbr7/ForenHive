from __future__ import annotations

import ipaddress
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import text

from db import session_scope

router = APIRouter(prefix="/api/risk-scores", tags=["Risk Scores"])


def _validate_ip(ip: str) -> str:
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid IP address: {ip}")
    return ip


@router.get("/{source_ip}/breakdown", response_model=Dict[str, Any])
async def get_signal_breakdown(source_ip: str):
    """Detailed signal breakdown for an IP (for dashboard charts)."""
    _validate_ip(source_ip)
    async with session_scope() as session:
        result = await session.execute(
            text(
                """
                SELECT source_ip, risk_score, risk_level,
                       signal_breakdown, honeypot_summary,
                       key_findings, recommendations
                FROM ip_risk_scores
                WHERE source_ip = CAST(:ip AS INET)
                LIMIT 1
                """
            ),
            {"ip": source_ip},
        )
        row = result.mappings().first()
        if not row:
            raise HTTPException(
                status_code=404,
                detail=f"No risk score found for {source_ip}. Run the forensic engine first.",
            )
        d = dict(row)
        d["source_ip"] = str(d["source_ip"])
        return d


@router.get("/{source_ip}", response_model=Dict[str, Any])
async def get_unified_risk_score(source_ip: str):
    """Unified risk score for a source IP (aggregates all honeypots)."""
    _validate_ip(source_ip)
    async with session_scope() as session:
        result = await session.execute(
            text(
                """
                SELECT source_ip, risk_score, risk_level, confidence, active_signals,
                       signal_breakdown, honeypots_hit, honeypot_count, honeypot_summary,
                       sessions_count, key_findings, recommendations,
                       enrichment_snapshot, scored_at, updated_at
                FROM ip_risk_scores
                WHERE source_ip = CAST(:ip AS INET)
                LIMIT 1
                """
            ),
            {"ip": source_ip},
        )
        row = result.mappings().first()
        if not row:
            raise HTTPException(
                status_code=404,
                detail=f"No risk score found for {source_ip}. Run the forensic engine first.",
            )
        d = dict(row)
        d["source_ip"] = str(d["source_ip"])
        return d


@router.get("/", response_model=Dict[str, Any])
async def list_risk_scores(
    risk_level: Optional[str] = Query(
        None,
        description="Filter by level: CRITICAL|HIGH|MEDIUM|LOW|INFO",
    ),
    min_score: int = Query(0, ge=0, le=100),
    limit: int = Query(100, ge=1, le=500),
) -> Dict[str, Any]:
    """List all unified IP risk scores, optionally filtered."""
    async with session_scope() as session:
        if risk_level:
            result = await session.execute(
                text(
                    """
                    SELECT source_ip, risk_score, risk_level, confidence,
                           honeypots_hit, honeypot_count, sessions_count,
                           active_signals, scored_at
                    FROM ip_risk_scores
                    WHERE risk_level = :level
                      AND risk_score >= :min_score
                    ORDER BY risk_score DESC
                    LIMIT :limit
                    """
                ),
                {"level": risk_level.upper(), "min_score": min_score, "limit": limit},
            )
        else:
            result = await session.execute(
                text(
                    """
                    SELECT source_ip, risk_score, risk_level, confidence,
                           honeypots_hit, honeypot_count, sessions_count,
                           active_signals, scored_at
                    FROM ip_risk_scores
                    WHERE risk_score >= :min_score
                    ORDER BY risk_score DESC
                    LIMIT :limit
                    """
                ),
                {"min_score": min_score, "limit": limit},
            )
        rows = result.mappings().all()
        items = []
        for r in rows:
            d = dict(r)
            d["source_ip"] = str(d["source_ip"])
            items.append(d)
        return {"total": len(items), "items": items}
