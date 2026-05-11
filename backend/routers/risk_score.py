from __future__ import annotations

import ipaddress
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import text

from db import session_scope

router = APIRouter(prefix="/api/risk-score", tags=["Risk Score"])


def _validate_ip(ip: str) -> str:
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid IP address: {ip}")
    return ip


@router.get("/{source_ip}", response_model=Dict[str, Any])
async def get_unified_risk_score(source_ip: str, hours: int = Query(24, ge=1, le=720)):
    """Unified risk score for a source IP (aggregates all honeypots)."""
    _validate_ip(source_ip)
    async with session_scope() as session:
        result = await session.execute(
            text(
                """
                SELECT session_id, source_ip, honeypots_hit, honeypot_count,
                       sessions_count, risk_score, risk_level, confidence,
                       signal_breakdown, kill_chain_stage, kill_chain_phase,
                       scored_at, updated_at
                FROM forensic_sessions
                WHERE source_ip = :ip
                  AND honeypot_type = 'unified'
                ORDER BY scored_at DESC
                LIMIT 1
                """
            ),
            {"ip": source_ip},
        )
        row = result.mappings().first()
        if not row:
            raise HTTPException(
                status_code=404,
                detail=f"No unified risk score found for {source_ip}. Run the forensic engine first.",
            )
        return dict(row)


@router.get("/", response_model=Dict[str, Any])
async def list_risk_scores(
    risk_level: Optional[str] = Query(None, description="Filter by risk level: CRITIQUE|ÉLEVÉ|MOYEN|FAIBLE|INFO"),
    min_score: int = Query(0, ge=0, le=100),
    limit: int = Query(100, ge=1, le=500),
) -> Dict[str, Any]:
    """List all unified IP risk scores, optionally filtered."""
    async with session_scope() as session:
        if risk_level:
            result = await session.execute(
                text(
                    """
                    SELECT source_ip, honeypots_hit, honeypot_count, sessions_count,
                           risk_score, risk_level, confidence, scored_at
                    FROM forensic_sessions
                    WHERE honeypot_type = 'unified'
                      AND risk_level = :level
                      AND risk_score >= :min_score
                    ORDER BY risk_score DESC
                    LIMIT :limit
                    """
                ),
                {"level": risk_level, "min_score": min_score, "limit": limit},
            )
        else:
            result = await session.execute(
                text(
                    """
                    SELECT source_ip, honeypots_hit, honeypot_count, sessions_count,
                           risk_score, risk_level, confidence, scored_at
                    FROM forensic_sessions
                    WHERE honeypot_type = 'unified'
                      AND risk_score >= :min_score
                    ORDER BY risk_score DESC
                    LIMIT :limit
                    """
                ),
                {"min_score": min_score, "limit": limit},
            )
        rows = result.mappings().all()
        return {"total": len(rows), "items": [dict(r) for r in rows]}
