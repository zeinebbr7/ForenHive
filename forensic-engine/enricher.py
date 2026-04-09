"""
ForenHive Forensic Engine — IP Enrichment
Enriches IPs with GeoIP, privacy detection, AbuseIPDB, Shodan, and Whois.
Results are cached in PostgreSQL (24h TTL).
"""

import ipaddress
import json
import logging
import os
import time
from datetime import datetime, timezone, timedelta
from typing import Optional

import psycopg2
import psycopg2.extras
import requests

import config

log = logging.getLogger("enricher")

# ── Helpers ────────────────────────────────────────────────────────────────────

def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)

# ── PostgreSQL cache ───────────────────────────────────────────────────────────

def _pg_conn():
    return psycopg2.connect(
        host=config.PG_HOST, port=config.PG_PORT,
        dbname=config.PG_DB, user=config.PG_USER,
        password=os.environ.get("PG_PASSWORD") or os.environ.get("POSTGRES_PASSWORD", "")
    )

# ── GeoIP (offline MaxMind) ────────────────────────────────────────────────────

def _load_geoip():
    try:
        import geoip2.database
        city_reader = geoip2.database.Reader(config.GEOIP_CITY_DB)
        asn_reader  = geoip2.database.Reader(config.GEOIP_ASN_DB)
        return city_reader, asn_reader
    except Exception as e:
        log.warning(f"GeoIP databases not available: {e}")
        return None, None

_city_reader, _asn_reader = _load_geoip()

def _geoip_lookup(ip: str) -> dict:
    result = {}
    if _city_reader:
        try:
            r = _city_reader.city(ip)
            result.update({
                "country":      r.country.name,
                "country_code": r.country.iso_code,
                "city":         r.city.name,
                "lat":          r.location.latitude,
                "lon":          r.location.longitude,
            })
        except Exception:
            pass
    if _asn_reader:
        try:
            r = _asn_reader.asn(ip)
            result.update({
                "asn": r.autonomous_system_number,
                "org": r.autonomous_system_organization,
            })
        except Exception:
            pass
    return result

# ── IPLocate (free, no key) ────────────────────────────────────────────────────

def _iplocate_lookup(ip: str) -> dict:
    try:
        resp = requests.get(
            f"https://www.iplocate.io/api/lookup/{ip}",
            timeout=10
        )
        if resp.status_code == 200:
            data = resp.json()
            return {
                "is_tor":     data.get("is_tor", False),
                "is_vpn":     data.get("is_vpn", False),
                "is_proxy":   data.get("is_proxy", False),
                "is_hosting": data.get("is_hosting", False),
            }
    except Exception as e:
        log.warning(f"IPLocate lookup failed for {ip}: {e}")
    return {}

# ── AbuseIPDB ─────────────────────────────────────────────────────────────────

def _abuseipdb_lookup(ip: str) -> dict:
    if not config.ABUSEIPDB_KEY:
        return {}
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": config.ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": "true"},
            timeout=10
        )
        if resp.status_code == 200:
            d = resp.json().get("data", {})
            return {
                "abuse_score":   d.get("abuseConfidenceScore", 0),
                "total_reports": d.get("totalReports", 0),
                "isp":           d.get("isp", ""),
                "is_tor":        d.get("isTor", False),
                "country_code":  d.get("countryCode", ""),
            }
        log.warning(f"AbuseIPDB returned {resp.status_code} for {ip}")
    except Exception as e:
        log.warning(f"AbuseIPDB lookup failed for {ip}: {e}")
    return {}

# ── InternetDB (Shodan free — no key required) ────────────────────────────────

def _shodan_lookup(ip: str) -> dict:
    """Uses Shodan InternetDB — free, no API key needed."""
    try:
        resp = requests.get(
            f"https://internetdb.shodan.io/{ip}",
            timeout=10
        )
        if resp.status_code == 200:
            data = resp.json()
            if "detail" in data:
                return {}
            return {
                "open_ports": data.get("ports", []),
                "vulns":      data.get("vulns", []),
                "hostnames":  data.get("hostnames", []),
                "cpes":       data.get("cpes", []),
                "tags":       data.get("tags", []),
            }
        log.warning(f"InternetDB returned {resp.status_code} for {ip}")
    except Exception as e:
        log.warning(f"InternetDB lookup failed for {ip}: {e}")
    return {}

# ── Whois / RDAP ──────────────────────────────────────────────────────────────

def _whois_lookup(ip: str) -> dict:
    try:
        from ipwhois import IPWhois
        result = IPWhois(ip).lookup_rdap(depth=1)
        network = result.get("network", {})
        return {
            "network": network.get("name", ""),
            "org":     result.get("asn_description", ""),
            "cidr":    network.get("cidr", ""),
        }
    except Exception as e:
        log.warning(f"Whois lookup failed for {ip}: {e}")
    return {}

# ── Main enrichment class ─────────────────────────────────────────────────────

class IPEnricher:

    def check_cache(self, ip: str) -> Optional[dict]:
        try:
            with _pg_conn() as conn:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    cur.execute(
                        "SELECT data FROM ip_enrichment_cache WHERE ip = %s AND expires_at > NOW()",
                        (ip,)
                    )
                    row = cur.fetchone()
                    if row:
                        return row["data"]
        except Exception as e:
            log.warning(f"Cache read failed for {ip}: {e}")
        return None

    def save_cache(self, ip: str, data: dict):
        expires = _now_utc() + timedelta(hours=config.ENRICHMENT_CACHE_TTL_HOURS)
        try:
            with _pg_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO ip_enrichment_cache (ip, data, cached_at, expires_at)
                        VALUES (%s, %s, NOW(), %s)
                        ON CONFLICT (ip) DO UPDATE
                            SET data = EXCLUDED.data,
                                cached_at = NOW(),
                                expires_at = EXCLUDED.expires_at
                        """,
                        (ip, json.dumps(data), expires)
                    )
                conn.commit()
        except Exception as e:
            log.warning(f"Cache write failed for {ip}: {e}")

    def enrich(self, ip: str) -> dict:
        """Full enrichment pipeline for a single IP."""
        # Return minimal record for private IPs
        if _is_private(ip):
            return {"ip": ip, "private": True}

        # Check cache first
        cached = self.check_cache(ip)
        if cached:
            log.debug(f"Cache hit for {ip}")
            return cached

        log.info(f"Enriching {ip} ...")

        # 1 — GeoIP (offline, no rate limit)
        geo = _geoip_lookup(ip)

        # 2 — IPLocate (free, no key)
        privacy = _iplocate_lookup(ip)

        # 3 — AbuseIPDB
        reputation = _abuseipdb_lookup(ip)

        # 4 — InternetDB (Shodan free, no key)
        infrastructure = _shodan_lookup(ip)

        # 5 — Whois/RDAP
        whois = _whois_lookup(ip)

        result = {
            "ip":             ip,
            "geo":            geo,
            "privacy":        privacy,
            "reputation":     reputation,
            "infrastructure": infrastructure,
            "whois":          whois,
            "enriched_at":    _now_utc().isoformat(),
        }

        self.save_cache(ip, result)
        return result

    def enrich_batch(self, ips: list) -> dict:
        """Enrich a list of IPs, skipping private and cached ones."""
        results = {}
        unique = list({ip for ip in ips if ip})
        log.info(f"Enriching batch of {len(unique)} unique IPs ...")
        for ip in unique:
            results[ip] = self.enrich(ip)
        return results

    def enrich_from_es(self, es_client, hours_back: int = 24) -> dict:
        """
        Query ES for distinct source.ip values in the last N hours,
        then enrich each one (skips private IPs and cache hits).
        """
        since = (_now_utc() - timedelta(hours=hours_back)).isoformat()
        query = {
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gte": since}}},
                        {"exists": {"field": "source.ip"}}
                    ]
                }
            },
            "aggs": {
                "unique_ips": {
                    "terms": {"field": "source.ip.keyword", "size": 10000}
                }
            }
        }
        resp = es_client.search(index=config.ES_INDEX, body=query)
        ips = [b["key"] for b in resp["aggregations"]["unique_ips"]["buckets"]]
        log.info(f"Found {len(ips)} unique source IPs in the last {hours_back}h")
        return self.enrich_batch(ips)
