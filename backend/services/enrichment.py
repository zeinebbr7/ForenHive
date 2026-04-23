from __future__ import annotations

import logging
from typing import Any, Dict, Optional

import httpx

from config import get_settings

log = logging.getLogger(__name__)


class EnrichmentService:
    def __init__(self) -> None:
        self.settings = get_settings()

    async def abuseipdb(self, ip: str) -> Dict[str, Any]:
        if not self.settings.abuseipdb_api_key:
            return {}
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": self.settings.abuseipdb_api_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""}
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(url, headers=headers, params=params)
                r.raise_for_status()
                data = r.json().get("data", {})
                return {
                    "abuseipdb_score": data.get("abuseConfidenceScore"),
                    "abuseipdb_reports": data.get("totalReports"),
                    "usage_type": data.get("usageType"),
                    "isp": data.get("isp"),
                    "domain": data.get("domain"),
                    "is_tor": bool(data.get("isTor")),
                }
        except Exception as exc:
            log.warning("AbuseIPDB lookup failed for %s: %s", ip, exc)
            return {}

    async def iplocate(self, ip: str) -> Dict[str, Any]:
        url = f"https://iplocate.io/api/lookup/{ip}"
        headers = {}
        if self.settings.iplocate_api_key:
            headers["X-API-Key"] = self.settings.iplocate_api_key
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(url, headers=headers)
                r.raise_for_status()
                data = r.json()
                threat = data.get("threat") or {}
                privacy = data.get("privacy") or {}
                return {
                    "is_tor": bool(threat.get("is_tor") or privacy.get("is_tor")),
                    "is_vpn": bool(threat.get("is_vpn") or privacy.get("is_vpn")),
                    "is_proxy": bool(threat.get("is_proxy") or privacy.get("is_proxy")),
                    "country": data.get("country"),
                    "country_iso": data.get("country_code"),
                    "city": data.get("city"),
                    "asn": (data.get("asn") or {}).get("asn") if isinstance(data.get("asn"), dict) else None,
                    "as_org": (data.get("asn") or {}).get("name") if isinstance(data.get("asn"), dict) else None,
                }
        except Exception as exc:
            log.warning("IPLocate lookup failed for %s: %s", ip, exc)
            return {}

    async def virustotal_hash(self, sha256: str) -> Dict[str, Any]:
        if not self.settings.virustotal_api_key:
            return {}
        url = f"https://www.virustotal.com/api/v3/files/{sha256}"
        headers = {"x-apikey": self.settings.virustotal_api_key}
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.get(url, headers=headers)
                if r.status_code == 404:
                    return {"found": False}
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


_svc: Optional[EnrichmentService] = None


def get_enrichment() -> EnrichmentService:
    global _svc
    if _svc is None:
        _svc = EnrichmentService()
    return _svc
