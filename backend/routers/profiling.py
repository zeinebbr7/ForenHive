"""
profiling.py — Profils criminologiques (Suspect Profiler)
Rôle : exposition des profils BAU générés par forensic-engine/profiler.py.
URL    : /api/profiling/*
Deps   : Elasticsearch (forenhive-suspect-profiles), PostgreSQL (suspect_profiles).
Auth   : Bearer token (forenhive.token) requis (sauf chat public).
Codes  : 200 OK | 401 non auth | 403 interdit | 404 absent | 422 valid | 500 engine.
"""

import ipaddress
from typing import Any

from db import session_scope
from fastapi import APIRouter, HTTPException, Query
from models.report import AttackerProfile
from services.elasticsearch import get_es
from services.profiler import build_profile
from sqlalchemy import text

router = APIRouter(prefix="/api/profiling", tags=["profiling"])


def _severity(score: float) -> str:
    # Mirrors forensic-engine/risk_thresholds.py v2.0.0.
    if score >= 70:
        return "CRITICAL"
    if score >= 45:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


async def _load_profiled_rows(limit: int) -> list[dict[str, Any]]:
    """Pull the curated attacker list from Postgres (forensic-engine output)
    and enrich each row with ES summary stats. The PG table is the source of
    truth: it only contains IPs the forensic engine actually profiled, so we
    avoid Zeek background-traffic leakage (Google/CDN response IPs) and we
    get the real risk_score instead of a null-filled ES average.
    """
    async with session_scope() as s:
        res = await s.execute(
            text(
                "SELECT id, source_ip, risk_score, profile "
                "FROM suspect_profiles "
                "ORDER BY risk_score DESC NULLS LAST, updated_at DESC "
                "LIMIT :lim"
            ),
            {"lim": limit},
        )
        rows = res.mappings().all()

    if not rows:
        return []

    ips = [r["source_ip"] for r in rows]
    stats = await get_es().stats_for_ips(ips)

    out: list[dict[str, Any]] = []
    for r in rows:
        prof = r["profile"] or {}
        score = float(r["risk_score"] or 0)
        st = stats.get(r["source_ip"], {})
        out.append(
            {
                "id": r["id"],
                "source_ip": r["source_ip"],
                "risk_score": score,
                "severity": _severity(score),
                "sophistication": prof.get("sophistication"),
                "primary_objective": prof.get("primary_objective"),
                "dominant_tactic": prof.get("dominant_tactic"),
                "mitre_techniques": prof.get("mitre_techniques") or [],
                "event_count": st.get("event_count", 0),
                "session_count": prof.get("session_count") or st.get("event_count", 0),
                "honeypots": st.get("honeypots") or [],
                "country": st.get("country"),
                "first_seen": st.get("first_seen"),
                "last_seen": st.get("last_seen"),
            }
        )
    return out


@router.get("", response_model=list[dict[str, Any]])
async def list_profiles(limit: int = Query(50, ge=1, le=200)) -> list[dict[str, Any]]:
    """Curated attacker list (PG suspect_profiles) enriched with ES stats."""
    return await _load_profiled_rows(limit)


@router.get("/stats/summary")
async def stats_summary() -> dict[str, Any]:
    """Severity-band counts + average risk across the top attackers."""
    rows = await _load_profiled_rows(limit=200)
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


# Rich behavioral fields produced by forensic-engine/profiler.py and stored in
# suspect_profiles.profile. AttackerProfile (Pydantic, extra="ignore") drops
# them on its own, so we merge them in explicitly after rebuilding from ES.
_PG_PROFILE_FIELDS = (
    "sophistication",
    "confidence",
    "primary_objective",
    "secondary_objective",
    "behavioral_traits",
    "organized_score",
    "disguise_used",
    "disguise_type",
    "escalation_detected",
    "dominant_tactic",
    "kill_chain_phase",
    "signature_indicators",
    "similar_past_cases",
    "detective_narrative",
    "actor_type",
)


def _merge_pg_profile(rebuilt: AttackerProfile, stored: dict[str, Any]) -> dict[str, Any]:
    out = rebuilt.model_dump()
    if not stored:
        return out
    for k in _PG_PROFILE_FIELDS:
        v = stored.get(k)
        if v not in (None, ""):
            out[k] = v
    # Prefer the stored mitre_techniques list if it has more entries than the
    # ES rebuild — events may have rotated out while the curated list persists.
    stored_mitre = stored.get("mitre_techniques") or []
    if len(stored_mitre) > len(out.get("mitre_techniques") or []):
        out["mitre_techniques"] = stored_mitre
    return out


@router.get("/by-id/{row_id}")
async def profile_by_id(row_id: int) -> dict[str, Any]:
    """Resolve a suspect_profiles.id (PG primary key) to a full profile by IP,
    merged with the rich behavioral fields stored in suspect_profiles.profile."""
    async with session_scope() as s:
        res = await s.execute(
            text("SELECT source_ip, profile FROM suspect_profiles WHERE id = :i"),
            {"i": row_id},
        )
        row = res.first()
    if not row:
        raise HTTPException(status_code=404, detail="profile row not found")
    rebuilt = await build_profile(row[0])
    return _merge_pg_profile(rebuilt, row[1] or {})


@router.get("/{ip}")
async def profile(ip: str) -> dict[str, Any]:
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid IP address")
    rebuilt = await build_profile(ip)
    async with session_scope() as s:
        res = await s.execute(
            text("SELECT profile FROM suspect_profiles WHERE source_ip = :ip"),
            {"ip": ip},
        )
        row = res.first()
    stored = (row[0] if row else None) or {}
    return _merge_pg_profile(rebuilt, stored)
