from fastapi import APIRouter, Query
<<<<<<< HEAD
from typing import Any, Dict, List
=======
>>>>>>> ismail

from services.elasticsearch import get_es

router = APIRouter(prefix="/api/geo", tags=["geo"])


<<<<<<< HEAD
async def _pg_geo_rows() -> List[Dict[str, Any]]:
    """Return per-country aggregates from PG forensic_sessions + ip_enrichment_cache."""
    try:
        from sqlalchemy import text
        from db import session_scope

        async with session_scope() as db:
            result = await db.execute(text("""
                SELECT
                    cache.data->'geo'->>'country_code'   AS country_iso,
                    cache.data->'geo'->>'country'        AS country_name,
                    COUNT(DISTINCT fs.source_ip)         AS unique_ips,
                    COUNT(fs.session_id)                 AS hits,
                    AVG(fs.risk_score)                   AS avg_risk
                FROM forensic_sessions fs
                JOIN ip_enrichment_cache cache ON cache.ip = fs.source_ip
                WHERE fs.honeypot_type != 'unified'
                  AND cache.data->'geo'->>'country_code' IS NOT NULL
                  AND cache.data->'geo'->>'country_code' != ''
                GROUP BY country_iso, country_name
            """))
            rows = []
            for row in result.mappings():
                avg_risk = float(row["avg_risk"] or 0)
                risk_level = (
                    "critical" if avg_risk >= 80
                    else "high" if avg_risk >= 60
                    else "medium" if avg_risk >= 40
                    else "low"
                )
                rows.append({
                    "country_iso":    row["country_iso"] or "??",
                    "country_name":   row["country_name"] or row["country_iso"] or "Unknown",
                    "unique_ips":     int(row["unique_ips"] or 0),
                    "hits":           int(row["hits"] or 0),
                    "avg_risk_score": round(avg_risk, 1),
                    "risk_level":     risk_level,
                    "source":         "pg",
                })
            return rows
    except Exception:
        return []


def _merge_geo(es_rows: List[Dict], pg_rows: List[Dict]) -> List[Dict]:
    """Merge ES and PG country rows, preferring PG data for overlapping countries."""
    merged: Dict[str, Dict] = {}

    for r in es_rows:
        key = r.get("country_iso", "??")
        merged[key] = dict(r)

    for r in pg_rows:
        key = r.get("country_iso", "??")
        if key in merged:
            existing = merged[key]
            existing["hits"] = existing.get("hits", 0) + r["hits"]
            existing["unique_ips"] = max(existing.get("unique_ips", 0), r["unique_ips"])
            total_hits = existing["hits"]
            es_hits = existing["hits"] - r["hits"]
            pg_hits = r["hits"]
            if total_hits > 0:
                blended = (existing.get("avg_risk_score", 0) * es_hits + r["avg_risk_score"] * pg_hits) / total_hits
                existing["avg_risk_score"] = round(blended, 1)
            existing["source"] = "merged"
        else:
            merged[key] = dict(r)

    result = sorted(merged.values(), key=lambda x: x.get("hits", 0), reverse=True)
    return result


@router.get("/breakdown")
async def geo_breakdown(top: int = Query(25, ge=1, le=200)):
    es_countries = await get_es().country_breakdown(top=top)
    pg_countries = await _pg_geo_rows()
    if pg_countries:
        countries = _merge_geo(es_countries, pg_countries)[:top]
    else:
        countries = es_countries
    return {"top": top, "countries": countries}


@router.get("/forensic-sessions")
async def forensic_sessions_geo(limit: int = Query(100, ge=1, le=500)):
    """Return PG forensic sessions with lat/lon from the enrichment cache.
    Used by the geomap page to overlay demo/enriched IPs on the map."""
    try:
        from sqlalchemy import text
        from db import session_scope

        async with session_scope() as db:
            result = await db.execute(text("""
                SELECT
                    fs.source_ip,
                    fs.honeypot_type,
                    fs.risk_score,
                    fs.risk_level,
                    COUNT(fs.session_id)                              AS sessions,
                    (cache.data->'geo'->>'lat')::float                AS lat,
                    (cache.data->'geo'->>'lon')::float                AS lon,
                    cache.data->'geo'->>'country_code'                AS country_code,
                    cache.data->'geo'->>'country'                     AS country_name,
                    cache.data->'geo'->>'city'                        AS city
                FROM forensic_sessions fs
                JOIN ip_enrichment_cache cache ON cache.ip = fs.source_ip
                WHERE fs.honeypot_type != 'unified'
                  AND (cache.data->'geo'->>'lat') IS NOT NULL
                GROUP BY fs.source_ip, fs.honeypot_type, fs.risk_score, fs.risk_level,
                         lat, lon, country_code, country_name, city
                ORDER BY fs.risk_score DESC NULLS LAST
                LIMIT :lim
            """), {"lim": limit})
            rows = []
            for row in result.mappings():
                lat = row["lat"]
                lon = row["lon"]
                if lat is None or lon is None:
                    continue
                rows.append({
                    "source_ip":    row["source_ip"],
                    "honeypot_type": row["honeypot_type"],
                    "risk_score":   row["risk_score"],
                    "risk_level":   row["risk_level"],
                    "sessions":     int(row["sessions"] or 1),
                    "lat":          float(lat),
                    "lon":          float(lon),
                    "country_code": row["country_code"] or "",
                    "country_name": row["country_name"] or "",
                    "city":         row["city"] or "",
                })
            return {"sessions": rows}
    except Exception as exc:
        return {"sessions": [], "error": str(exc)}
=======
@router.get("/breakdown")
async def geo_breakdown(top: int = Query(25, ge=1, le=200)):
    return {"top": top, "countries": await get_es().country_breakdown(top=top)}
>>>>>>> ismail


@router.get("/honeypot-split")
async def honeypot_split():
    return {"split": await get_es().honeypot_split()}
