from __future__ import annotations

import json
import logging
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from config import get_settings
from db import session_scope
from sqlalchemy import text

from services.quota_tracker import get_tracker

log = logging.getLogger(__name__)

# IP-level lookups (abuseipdb + iplocate) are cached in ip_enrichment_cache
# under a single jsonb row per IP. ~1h TTL is long enough to absorb the
# typical report-regeneration burst without re-burning daily quota, short
# enough that ground-truth changes (Tor exit-list updates, fresh abuse
# reports) propagate the same day. virustotal_hash is keyed by SHA-256 and
# uses file_analysis (no per-call cache here — it's already cheap to look
# up once and the engine populates it).
_IP_CACHE_TTL = timedelta(hours=1)


async def _ip_cache_read(ip: str) -> dict[str, Any] | None:
    try:
        async with session_scope() as db:
            row = (
                (
                    await db.execute(
                        text(
                            "SELECT data, expires_at FROM ip_enrichment_cache "
                            "WHERE ip = :ip LIMIT 1"
                        ),
                        {"ip": ip},
                    )
                )
                .mappings()
                .fetchone()
            )
            if not row:
                return None
            exp = row["expires_at"]
            if exp is not None:
                # Cached row stored without tz info; compare naive-utc-safe.
                now_naive = datetime.now(UTC).replace(tzinfo=None)
                if hasattr(exp, "tzinfo") and exp.tzinfo is not None:
                    now_naive = datetime.now(UTC)
                if exp <= now_naive:
                    return None
            data = row["data"]
            if isinstance(data, str):
                try:
                    data = json.loads(data)
                except Exception:
                    return None
            return data if isinstance(data, dict) else None
    except Exception as exc:
        log.debug("ip_enrichment_cache read failed for %s: %s", ip, exc)
        return None


async def _ip_cache_write(ip: str, key: str, payload: dict[str, Any]) -> None:
    """Merge `payload` under `data[key]` so abuseipdb + iplocate can share a row."""
    if not payload:
        return
    expires_at = datetime.now(UTC).replace(tzinfo=None) + _IP_CACHE_TTL
    try:
        async with session_scope() as db:
            existing = (
                (
                    await db.execute(
                        text("SELECT data FROM ip_enrichment_cache WHERE ip = :ip LIMIT 1"),
                        {"ip": ip},
                    )
                )
                .mappings()
                .fetchone()
            )
            merged: dict[str, Any] = {}
            if existing and existing["data"]:
                d = existing["data"]
                if isinstance(d, str):
                    try:
                        d = json.loads(d)
                    except Exception:
                        d = {}
                if isinstance(d, dict):
                    merged = d
            merged[key] = payload
            await db.execute(
                text(
                    """
                    INSERT INTO ip_enrichment_cache (ip, data, cached_at, expires_at)
                    VALUES (:ip, CAST(:data AS jsonb), NOW(), :exp)
                    ON CONFLICT (ip) DO UPDATE
                        SET data = EXCLUDED.data,
                            cached_at = NOW(),
                            expires_at = EXCLUDED.expires_at
                    """
                ),
                {"ip": ip, "data": json.dumps(merged), "exp": expires_at},
            )
            await db.commit()
    except Exception as exc:
        log.debug("ip_enrichment_cache write failed for %s: %s", ip, exc)


class EnrichmentService:
    def __init__(self) -> None:
        self.settings = get_settings()

    async def abuseipdb(self, ip: str) -> dict[str, Any]:
        if not self.settings.abuseipdb_api_key:
            return {}
        # Cache + quota gate — see module docstring.
        cached = await _ip_cache_read(ip)
        if cached and isinstance(cached.get("backend_abuseipdb"), dict):
            return cached["backend_abuseipdb"]
        tracker = get_tracker()
        if await tracker.is_exhausted("abuseipdb"):
            log.info("AbuseIPDB skipped for %s (quota exhausted)", ip)
            return {}
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": self.settings.abuseipdb_api_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""}
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(url, headers=headers, params=params)
                if r.status_code in (429, 403):
                    await tracker.mark_exhausted("abuseipdb", f"HTTP {r.status_code}")
                    return {}
                if r.status_code == 401:
                    await tracker.mark_exhausted("abuseipdb", "HTTP 401 (invalid key)")
                    return {}
                r.raise_for_status()
                data = r.json().get("data", {})
                payload = {
                    "abuseipdb_score": data.get("abuseConfidenceScore"),
                    "abuseipdb_reports": data.get("totalReports"),
                    "usage_type": data.get("usageType"),
                    "isp": data.get("isp"),
                    "domain": data.get("domain"),
                    "is_tor": bool(data.get("isTor")),
                }
                await _ip_cache_write(ip, "backend_abuseipdb", payload)
                return payload
        except Exception as exc:
            log.warning("AbuseIPDB lookup failed for %s: %s", ip, exc)
            return {}

    async def iplocate(self, ip: str) -> dict[str, Any]:
        cached = await _ip_cache_read(ip)
        if cached and isinstance(cached.get("backend_iplocate"), dict):
            return cached["backend_iplocate"]
        tracker = get_tracker()
        if await tracker.is_exhausted("iplocate"):
            log.info("IPLocate skipped for %s (quota exhausted)", ip)
            return {}
        url = f"https://iplocate.io/api/lookup/{ip}"
        headers = {}
        if self.settings.iplocate_api_key:
            headers["X-API-Key"] = self.settings.iplocate_api_key
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(url, headers=headers)
                if r.status_code in (429, 403):
                    await tracker.mark_exhausted("iplocate", f"HTTP {r.status_code}")
                    return {}
                r.raise_for_status()
                data = r.json()
                threat = data.get("threat") or {}
                privacy = data.get("privacy") or {}
                payload = {
                    "is_tor": bool(threat.get("is_tor") or privacy.get("is_tor")),
                    "is_vpn": bool(threat.get("is_vpn") or privacy.get("is_vpn")),
                    "is_proxy": bool(threat.get("is_proxy") or privacy.get("is_proxy")),
                    "country": data.get("country"),
                    "country_iso": data.get("country_code"),
                    "city": data.get("city"),
                    "asn": (data.get("asn") or {}).get("asn")
                    if isinstance(data.get("asn"), dict)
                    else None,
                    "as_org": (data.get("asn") or {}).get("name")
                    if isinstance(data.get("asn"), dict)
                    else None,
                }
                await _ip_cache_write(ip, "backend_iplocate", payload)
                return payload
        except Exception as exc:
            log.warning("IPLocate lookup failed for %s: %s", ip, exc)
            return {}

    async def virustotal_hash(self, sha256: str) -> dict[str, Any]:
        if not self.settings.virustotal_api_key:
            return {}
        tracker = get_tracker()
        if await tracker.is_exhausted("virustotal"):
            log.info("VirusTotal skipped for %s (quota exhausted)", sha256)
            return {"found": False, "skipped": True, "reason": "quota_exhausted"}
        url = f"https://www.virustotal.com/api/v3/files/{sha256}"
        headers = {"x-apikey": self.settings.virustotal_api_key}
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.get(url, headers=headers)
                if r.status_code == 404:
                    return {"found": False}
                if r.status_code in (429, 403):
                    await tracker.mark_exhausted("virustotal", f"HTTP {r.status_code}")
                    return {"found": False, "skipped": True, "reason": f"HTTP {r.status_code}"}
                r.raise_for_status()
                data = r.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                return {
                    "found": True,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "reputation": data.get("reputation"),
                    "names": data.get("names", [])[:5],
                }
        except Exception as exc:
            log.warning("VirusTotal lookup failed for %s: %s", sha256, exc)
            return {}


_svc: EnrichmentService | None = None


def get_enrichment() -> EnrichmentService:
    global _svc
    if _svc is None:
        _svc = EnrichmentService()
    return _svc
