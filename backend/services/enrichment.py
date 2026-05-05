from __future__ import annotations

import asyncio
import logging
from functools import partial
from typing import Any, Dict, Optional

import httpx

from config import get_settings

log = logging.getLogger(__name__)

_CITY_DB = "/app/GeoLite2-City.mmdb"
_ASN_DB  = "/app/GeoLite2-ASN.mmdb"


def _maxmind_geo(ip: str) -> Dict[str, Any]:
    """Offline GeoIP lookup using local MaxMind mmdb files."""
    try:
        import geoip2.database
        import geoip2.errors
    except ImportError:
        return {}

    result: Dict[str, Any] = {}

    try:
        with geoip2.database.Reader(_CITY_DB) as reader:
            r = reader.city(ip)
            result["country"] = r.country.name
            result["country_iso"] = r.country.iso_code
            result["city"] = r.city.name
            if r.location.latitude is not None and r.location.longitude is not None:
                result["latitude"] = r.location.latitude
                result["longitude"] = r.location.longitude
    except Exception:
        pass

    try:
        with geoip2.database.Reader(_ASN_DB) as reader:
            r = reader.asn(ip)
            result["asn"] = r.autonomous_system_number
            result["as_org"] = r.autonomous_system_organization
    except Exception:
        pass

    return result


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
                result = {
                    "is_tor": bool(threat.get("is_tor") or privacy.get("is_tor")),
                    "is_vpn": bool(threat.get("is_vpn") or privacy.get("is_vpn")),
                    "is_proxy": bool(threat.get("is_proxy") or privacy.get("is_proxy")),
                    "country": data.get("country"),
                    "country_iso": data.get("country_code"),
                    "city": data.get("city"),
                    "asn": (data.get("asn") or {}).get("asn") if isinstance(data.get("asn"), dict) else None,
                    "as_org": (data.get("asn") or {}).get("name") if isinstance(data.get("asn"), dict) else None,
                }
                # Fill any missing geo fields from MaxMind
                if not result.get("country") or not result.get("city") or not result.get("as_org"):
                    mm = _maxmind_geo(ip)
                    result.setdefault("country", mm.get("country"))
                    result.setdefault("country_iso", mm.get("country_iso"))
                    result.setdefault("city", mm.get("city"))
                    result.setdefault("asn", mm.get("asn"))
                    result.setdefault("as_org", mm.get("as_org"))
                    if "latitude" not in result and "latitude" in mm:
                        result["latitude"] = mm["latitude"]
                        result["longitude"] = mm["longitude"]
                return result
        except Exception as exc:
            log.warning("IPLocate lookup failed for %s: %s — falling back to MaxMind", ip, exc)
            mm = _maxmind_geo(ip)
            if not mm:
                return {}
            return {
                "country": mm.get("country"),
                "country_iso": mm.get("country_iso"),
                "city": mm.get("city"),
                "asn": mm.get("asn"),
                "as_org": mm.get("as_org"),
                "latitude": mm.get("latitude"),
                "longitude": mm.get("longitude"),
                "is_tor": False,
                "is_vpn": False,
                "is_proxy": False,
            }

    async def shodan_internetdb(self, ip: str) -> Dict[str, Any]:
        """Free Shodan InternetDB — open ports, CVEs, hostnames. No API key needed."""
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(f"https://internetdb.shodan.io/{ip}")
                if r.status_code == 404:
                    return {}
                if r.status_code == 429:
                    log.warning("Shodan InternetDB rate-limited for %s", ip)
                    return {}
                r.raise_for_status()
                data = r.json()
                if "detail" in data:
                    return {}
                return {
                    "open_ports": data.get("ports") or [],
                    "vulns":      data.get("vulns") or [],
                    "hostnames":  data.get("hostnames") or [],
                    "cpes":       data.get("cpes") or [],
                    "tags":       data.get("tags") or [],
                }
        except Exception as exc:
            log.warning("Shodan InternetDB lookup failed for %s: %s", ip, exc)
            return {}

    async def whois(self, ip: str) -> Dict[str, Any]:
        """RDAP/WHOIS lookup via ipwhois (sync, run in thread executor).
        Falls back to static RFC1918 metadata for private addresses."""
        def _lookup() -> Dict[str, Any]:
            import ipaddress as _ipaddress
            _RFC1918 = [
                ("10.0.0.0/8",      "PRIVATE-ADDRESS-10",     "NET-10-0-0-0-1",   "1994-03-15"),
                ("172.16.0.0/12",   "PRIVATE-ADDRESS-BBLK",   "NET-172-16-0-0-1", "1994-03-15"),
                ("192.168.0.0/16",  "PRIVATE-ADDRESS-CBLK",   "NET-192-168-0-0-1","1994-03-15"),
                ("127.0.0.0/8",     "LOOPBACK",                "NET-127-0-0-0-2",  "1994-03-15"),
                ("169.254.0.0/16",  "LINK-LOCAL",              "NET-169-254-0-0-1","2001-04-14"),
            ]
            try:
                addr = _ipaddress.ip_address(ip)
                for cidr, name, handle, reg in _RFC1918:
                    if addr in _ipaddress.ip_network(cidr):
                        return {
                            "network_name":    name,
                            "network_cidr":    cidr,
                            "network_type":    "IANA Special Use / RFC 1918",
                            "asn":             None,
                            "asn_description": "Internet Assigned Numbers Authority (IANA)",
                            "registration":    reg,
                            "abuse_contact":   ["abuse@iana.org"],
                            "is_private":      True,
                        }
            except ValueError:
                pass

            try:
                from ipwhois import IPWhois
                result = IPWhois(ip).lookup_rdap(depth=1)
                network = result.get("network") or {}
                events = network.get("events") or []
                registration = next(
                    (e.get("timestamp") for e in events if e.get("action") == "registration"), ""
                )
                abuse_emails: list = []
                for obj in (result.get("objects") or {}).values():
                    if "abuse" in (obj.get("roles") or []):
                        for entry in (obj.get("contact", {}).get("email") or []):
                            val = entry.get("value") if isinstance(entry, dict) else entry
                            if val:
                                abuse_emails.append(val)
                return {
                    "network_name":    network.get("name") or "",
                    "network_cidr":    network.get("cidr") or result.get("asn_cidr") or "",
                    "network_type":    network.get("type") or "",
                    "asn":             result.get("asn"),
                    "asn_description": result.get("asn_description") or "",
                    "registration":    registration,
                    "abuse_contact":   list(set(abuse_emails)),
                }
            except Exception as exc:
                log.warning("WHOIS lookup failed for %s: %s", ip, exc)
                return {}

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _lookup)

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
