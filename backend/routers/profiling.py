import ipaddress
<<<<<<< HEAD
<<<<<<< HEAD
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query

from models.report import AttackerProfile
from services.elasticsearch import get_es
=======
=======
>>>>>>> ismail

from fastapi import APIRouter, HTTPException

from models.report import AttackerProfile
<<<<<<< HEAD
>>>>>>> ismail
=======
>>>>>>> ismail
from services.profiler import build_profile

router = APIRouter(prefix="/api/profiling", tags=["profiling"])


<<<<<<< HEAD
<<<<<<< HEAD
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


=======
>>>>>>> ismail
=======
>>>>>>> ismail
@router.get("/{ip}", response_model=AttackerProfile)
async def profile(ip: str) -> AttackerProfile:
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid IP address")
    return await build_profile(ip)
