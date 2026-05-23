"""
ForenHive Forensic Engine — IP Enrichment

Aggregates the maximum amount of useful intelligence per IP from every
available source. The pipeline runs offline-first (MaxMind) and falls back
to free public APIs (IPLocate, Shodan InternetDB, AbuseIPDB) plus optional
paid Shodan when SHODAN_KEY is set.

Sources combined per IP:
  • MaxMind GeoLite2 City + ASN  (offline, country/city/lat-lon/asn/org)
  • IPLocate                     (privacy flags, ASN, company, abuse contact)
  • AbuseIPDB                    (abuse score, reports, usage_type, hostnames)
  • Shodan InternetDB (free)     (open ports, vulns, hostnames, cpes, tags)
  • Shodan host API (optional)   (banners, OS, services, last_update)
  • RDAP/Whois                   (network, CIDR, abuse contact, registration)
  • Reverse DNS (PTR)            (hostnames)

Plus a derived "threat_summary" flattening the most-actionable signals.
Results cached in PostgreSQL (24h TTL).
"""

import ipaddress
import json
import logging
import socket
from datetime import UTC, datetime, timedelta

import config
import psycopg2
import psycopg2.extras
import requests
from quota_tracker import get_tracker
from requests.adapters import HTTPAdapter

log = logging.getLogger("enricher")
_tracker = get_tracker()

HTTP_TIMEOUT = 10

# Module-level pooled session — reuses TCP/TLS across all enrichment lookups.
_http = requests.Session()
_http.mount("https://", HTTPAdapter(pool_connections=10, pool_maxsize=10))
_http.mount("http://", HTTPAdapter(pool_connections=10, pool_maxsize=10))

# ── Helpers ────────────────────────────────────────────────────────────────────


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True


def _classify_private_ip(ip: str) -> dict:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {
            "network_class": "private_unknown",
            "is_docker": False,
            "private_risk_level": "monitor",
        }

    if addr.is_loopback:
        return {"network_class": "loopback", "is_docker": False, "private_risk_level": "ignore"}

    docker_nets = [
        ipaddress.ip_network("172.17.0.0/16"),
        ipaddress.ip_network("172.18.0.0/16"),
        ipaddress.ip_network("172.19.0.0/16"),
    ]
    if any(addr in net for net in docker_nets):
        return {"network_class": "docker_bridge", "is_docker": True, "private_risk_level": "ignore"}

    try:
        vpn_ranges = [
            ipaddress.ip_network(r.strip())
            for r in config.PRIVATE_VPN_RANGES.split(",")
            if r.strip()
        ]
    except Exception:
        vpn_ranges = []
    if any(addr in net for net in vpn_ranges):
        return {
            "network_class": "vpn_tunnel",
            "is_docker": False,
            "private_risk_level": "investigate",
        }

    if addr in ipaddress.ip_network("10.0.0.0/8"):
        return {
            "network_class": "corporate_internal",
            "is_docker": False,
            "private_risk_level": "high",
        }
    if addr in ipaddress.ip_network("172.16.0.0/12"):
        return {
            "network_class": "corporate_internal",
            "is_docker": False,
            "private_risk_level": "high",
        }
    if addr in ipaddress.ip_network("192.168.0.0/16"):
        return {
            "network_class": "corporate_internal",
            "is_docker": False,
            "private_risk_level": "high",
        }

    return {"network_class": "private_unknown", "is_docker": False, "private_risk_level": "monitor"}


def _now_utc() -> datetime:
    return datetime.now(UTC)


# ── PostgreSQL cache ───────────────────────────────────────────────────────────

import db_pool  # noqa: E402  (import tardif intentionnel)


def _pg_conn():
    return db_pool.pooled_conn()


# ── GeoIP (offline MaxMind) ────────────────────────────────────────────────────


def _load_geoip():
    try:
        import geoip2.database

        city_reader = geoip2.database.Reader(config.GEOIP_CITY_DB)
        asn_reader = geoip2.database.Reader(config.GEOIP_ASN_DB)
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
            subdivision = r.subdivisions.most_specific
            result.update(
                {
                    "continent": r.continent.name,
                    "continent_code": r.continent.code,
                    "country": r.country.name,
                    "country_code": r.country.iso_code,
                    "country_eu": bool(r.country.is_in_european_union),
                    "registered_country": r.registered_country.name,
                    "region": subdivision.name,
                    "region_code": subdivision.iso_code,
                    "city": r.city.name,
                    "postal_code": r.postal.code,
                    "lat": r.location.latitude,
                    "lon": r.location.longitude,
                    "accuracy_radius_km": r.location.accuracy_radius,
                    "timezone": r.location.time_zone,
                    "metro_code": r.location.metro_code,
                }
            )
            try:
                result["network_cidr"] = str(r.traits.network)
            except Exception:
                pass
        except Exception:
            pass
    if _asn_reader:
        try:
            r = _asn_reader.asn(ip)
            result.update(
                {
                    "asn": r.autonomous_system_number,
                    "org": r.autonomous_system_organization,
                    "asn_network": str(r.network) if r.network else None,
                }
            )
        except Exception:
            pass
    return result


# ── IPLocate (free, no key) ────────────────────────────────────────────────────


def _iplocate_lookup(ip: str) -> dict:
    """Pulls full IPLocate response — ASN, company, privacy, abuse contact."""
    if _tracker.is_exhausted("iplocate"):
        return {}
    try:
        resp = _http.get(f"https://www.iplocate.io/api/lookup/{ip}", timeout=HTTP_TIMEOUT)
        if resp.status_code == 200:
            d = resp.json()
            asn = d.get("asn") or {}
            company = d.get("company") or {}
            privacy = d.get("privacy") or {}
            abuse = d.get("abuse") or {}
            return {
                # privacy flags
                "is_tor": bool(privacy.get("is_tor", d.get("is_tor", False))),
                "is_vpn": bool(privacy.get("is_vpn", d.get("is_vpn", False))),
                "is_proxy": bool(privacy.get("is_proxy", d.get("is_proxy", False))),
                "is_hosting": bool(privacy.get("is_hosting", d.get("is_hosting", False))),
                "is_relay": bool(privacy.get("is_relay", False)),
                "is_anonymous": bool(privacy.get("is_anonymous", False)),
                "is_abuser": bool(privacy.get("is_abuser", False)),
                "is_datacenter": bool(privacy.get("is_datacenter", False)),
                "is_bogon": bool(d.get("is_bogon", False)),
                # network / org details
                "asn_number": asn.get("asn") or d.get("asn"),
                "asn_name": asn.get("name"),
                "asn_route": asn.get("route"),
                "asn_country": asn.get("country_code"),
                "asn_type": asn.get("type"),
                "asn_domain": asn.get("domain"),
                "company_name": company.get("name"),
                "company_domain": company.get("domain"),
                "company_type": company.get("type"),
                # location supplement
                "iplocate_country": d.get("country"),
                "iplocate_country_code": d.get("country_code"),
                "iplocate_city": d.get("city"),
                "iplocate_subdivision": d.get("subdivision"),
                "iplocate_postal_code": d.get("postal_code"),
                "iplocate_time_zone": d.get("time_zone"),
                "iplocate_continent": d.get("continent"),
                # abuse contact
                "abuse_contact_email": abuse.get("email"),
                "abuse_contact_phone": abuse.get("phone"),
                "abuse_contact_name": abuse.get("name"),
                "abuse_contact_address": abuse.get("address"),
            }
        if resp.status_code in (429, 403):
            _tracker.mark_exhausted("iplocate", reason=f"HTTP {resp.status_code}")
        else:
            log.warning(f"IPLocate returned {resp.status_code} for {ip}")
    except Exception as e:
        log.warning(f"IPLocate lookup failed for {ip}: {e}")
    return {}


# ── AbuseIPDB ─────────────────────────────────────────────────────────────────


def _abuseipdb_lookup(ip: str) -> dict:
    """Verbose lookup — pulls reports, usage type, hostnames, last reported."""
    if not config.ABUSEIPDB_KEY:
        return {}
    if _tracker.is_exhausted("abuseipdb"):
        return {}
    try:
        resp = _http.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": config.ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": "true"},
            timeout=HTTP_TIMEOUT,
        )
        if resp.status_code == 200:
            d = resp.json().get("data", {})
            reports = d.get("reports", []) or []
            # Aggregate distinct attack categories from recent reports
            categories = set()
            for r in reports:
                for c in r.get("categories") or []:
                    categories.add(int(c))
            # Most-recent comment for human context
            recent_comments = [
                (r.get("comment") or "").strip() for r in reports[:5] if r.get("comment")
            ]
            return {
                "abuse_score": d.get("abuseConfidenceScore", 0),
                "total_reports": d.get("totalReports", 0),
                "distinct_users": d.get("numDistinctUsers", 0),
                "last_reported_at": d.get("lastReportedAt", ""),
                "is_whitelisted": bool(d.get("isWhitelisted") or False),
                "is_public": bool(d.get("isPublic", True)),
                "ip_version": d.get("ipVersion"),
                "usage_type": d.get("usageType", ""),
                "isp": d.get("isp", ""),
                "domain": d.get("domain", ""),
                "hostnames": d.get("hostnames", []) or [],
                "is_tor": bool(d.get("isTor", False)),
                "country_code": d.get("countryCode", ""),
                "country_name": d.get("countryName", ""),
                "report_categories": sorted(categories),
                "recent_comments": recent_comments,
            }
        if resp.status_code == 429:
            _tracker.mark_exhausted("abuseipdb", reason="HTTP 429")
        elif resp.status_code == 401:
            _tracker.mark_exhausted("abuseipdb", reason="HTTP 401 (invalid key)")
        else:
            log.warning(f"AbuseIPDB returned {resp.status_code} for {ip}")
    except Exception as e:
        log.warning(f"AbuseIPDB lookup failed for {ip}: {e}")
    return {}


# ── Shodan ────────────────────────────────────────────────────────────────────


def _shodan_internetdb(ip: str) -> dict:
    """Free Shodan InternetDB — open ports, CVEs, hostnames, CPEs, tags."""
    if _tracker.is_exhausted("shodan"):
        return {}
    try:
        resp = _http.get(f"https://internetdb.shodan.io/{ip}", timeout=HTTP_TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            if "detail" in data:
                return {}
            return {
                "open_ports": data.get("ports", []) or [],
                "vulns": data.get("vulns", []) or [],
                "hostnames": data.get("hostnames", []) or [],
                "cpes": data.get("cpes", []) or [],
                "tags": data.get("tags", []) or [],
            }
        if resp.status_code == 429:
            _tracker.mark_exhausted("shodan", reason="HTTP 429")
        elif resp.status_code != 404:
            log.warning(f"InternetDB returned {resp.status_code} for {ip}")
    except Exception as e:
        log.warning(f"InternetDB lookup failed for {ip}: {e}")
    return {}


def _shodan_host_api(ip: str) -> dict:
    """Paid Shodan host API — banners, OS, services. Only runs if SHODAN_KEY set."""
    if not getattr(config, "SHODAN_KEY", ""):
        return {}
    if _tracker.is_exhausted("shodan_host"):
        return {}
    try:
        resp = _http.get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": config.SHODAN_KEY, "minify": "false"},
            timeout=HTTP_TIMEOUT,
        )
        if resp.status_code == 200:
            d = resp.json()
            services = []
            for svc in (d.get("data") or [])[:25]:
                services.append(
                    {
                        "port": svc.get("port"),
                        "transport": svc.get("transport"),
                        "product": svc.get("product"),
                        "version": svc.get("version"),
                        "module": (svc.get("_shodan") or {}).get("module"),
                        "banner": (svc.get("data") or "")[:500],
                        "ssl_cert_subject": ((svc.get("ssl") or {}).get("cert") or {}).get(
                            "subject"
                        ),
                    }
                )
            return {
                "os": d.get("os"),
                "organization": d.get("org"),
                "isp": d.get("isp"),
                "last_update": d.get("last_update"),
                "asn": d.get("asn"),
                "country": d.get("country_name"),
                "city": d.get("city"),
                "ports_detail": d.get("ports", []),
                "services": services,
                "host_tags": d.get("tags", []),
            }
        if resp.status_code in (401, 403):
            _tracker.mark_exhausted("shodan_host", reason=f"HTTP {resp.status_code} (key issue)")
        elif resp.status_code == 429:
            _tracker.mark_exhausted("shodan_host", reason="HTTP 429")
        elif resp.status_code != 404:
            log.warning(f"Shodan host API returned {resp.status_code} for {ip}")
    except Exception as e:
        log.warning(f"Shodan host lookup failed for {ip}: {e}")
    return {}


def _shodan_lookup(ip: str) -> dict:
    """Combine free InternetDB with paid host API when available."""
    base = _shodan_internetdb(ip)
    host = _shodan_host_api(ip)
    if host:
        base["host_detail"] = host
    return base


# ── Whois / RDAP ──────────────────────────────────────────────────────────────


def _whois_lookup(ip: str) -> dict:
    try:
        from ipwhois import IPWhois

        result = IPWhois(ip).lookup_rdap(depth=1)
        network = result.get("network", {}) or {}
        events = network.get("events", []) or []
        registration = next(
            (e.get("timestamp") for e in events if e.get("action") == "registration"), ""
        )
        last_changed = next(
            (e.get("timestamp") for e in events if e.get("action") == "last changed"), ""
        )
        # Pull abuse contact email from objects
        abuse_emails = []
        for obj in (result.get("objects") or {}).values():
            roles = obj.get("roles") or []
            if "abuse" in roles:
                vcard = obj.get("contact", {}).get("email") or []
                for entry in vcard:
                    val = entry.get("value") if isinstance(entry, dict) else entry
                    if val:
                        abuse_emails.append(val)
        return {
            "network_name": network.get("name", ""),
            "network_handle": network.get("handle", ""),
            "network_type": network.get("type", ""),
            "cidr": network.get("cidr", ""),
            "country": network.get("country", ""),
            "asn": result.get("asn"),
            "asn_description": result.get("asn_description", ""),
            "asn_country": result.get("asn_country_code", ""),
            "asn_registry": result.get("asn_registry", ""),
            "asn_cidr": result.get("asn_cidr", ""),
            "registration": registration,
            "last_changed": last_changed,
            "abuse_emails": list(set(abuse_emails)),
        }
    except Exception as e:
        log.warning(f"Whois lookup failed for {ip}: {e}")
    return {}


# ── Reverse DNS ───────────────────────────────────────────────────────────────


def _reverse_dns(ip: str, timeout_sec: float | None = None) -> dict:
    """Reverse DNS lookup with hard timeout (gethostbyaddr ignores socket default timeout)."""
    import concurrent.futures

    if timeout_sec is None:
        timeout_sec = config.DNS_LOOKUP_TIMEOUT_SEC
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(socket.gethostbyaddr, ip)
            host, aliases, _ = future.result(timeout=timeout_sec)
        return {"ptr": host, "aliases": aliases or []}
    except Exception:
        return {}


# ── Threat summary (derived) ──────────────────────────────────────────────────

# AbuseIPDB category IDs → human label (https://www.abuseipdb.com/categories)
_ABUSE_CATEGORIES = {
    1: "DNS Compromise",
    2: "DNS Poisoning",
    3: "Fraud Orders",
    4: "DDoS Attack",
    5: "FTP Brute-Force",
    6: "Ping of Death",
    7: "Phishing",
    8: "Fraud VoIP",
    9: "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted",
}


def _build_threat_summary(geo, privacy, reputation, infra, whois, dns) -> dict:
    """Flatten the most-actionable signals from all sources into one block."""
    cats = reputation.get("report_categories", []) or []
    category_labels = [_ABUSE_CATEGORIES.get(int(c), f"cat_{c}") for c in cats]

    # Anonymization indicator (any source agreeing)
    is_tor = bool(privacy.get("is_tor") or reputation.get("is_tor"))
    is_vpn = bool(privacy.get("is_vpn"))
    is_proxy = bool(privacy.get("is_proxy") or privacy.get("is_relay"))
    anonymized = is_tor or is_vpn or is_proxy or bool(privacy.get("is_anonymous"))

    # Hosting / datacenter (often = scanner / botnet C2)
    is_datacenter = bool(privacy.get("is_datacenter") or privacy.get("is_hosting"))

    # Aggregated hostnames across sources
    hostnames = set()
    for h in reputation.get("hostnames") or []:
        if h:
            hostnames.add(h)
    for h in infra.get("hostnames") or []:
        if h:
            hostnames.add(h)
    if dns.get("ptr"):
        hostnames.add(dns["ptr"])

    # Threat tier
    score = int(reputation.get("abuse_score") or 0)
    has_vulns = bool(infra.get("vulns"))
    if score >= 75 or has_vulns:
        tier = "high"
    elif score >= 25 or anonymized or is_datacenter:
        tier = "medium"
    elif score > 0:
        tier = "low"
    else:
        tier = "clean"

    return {
        "tier": tier,
        "abuse_score": score,
        "total_reports": int(reputation.get("total_reports") or 0),
        "distinct_reporters": int(reputation.get("distinct_users") or 0),
        "last_reported_at": reputation.get("last_reported_at", ""),
        "attack_categories": category_labels,
        "usage_type": reputation.get("usage_type", ""),
        "is_tor": is_tor,
        "is_vpn": is_vpn,
        "is_proxy": is_proxy,
        "is_anonymized": anonymized,
        "is_datacenter": is_datacenter,
        "is_abuser_listed": bool(privacy.get("is_abuser")),
        "is_whitelisted": bool(reputation.get("is_whitelisted")),
        "is_bogon": bool(privacy.get("is_bogon")),
        "open_ports": infra.get("open_ports", []) or [],
        "known_vulns": infra.get("vulns", []) or [],
        "shodan_tags": infra.get("tags", []) or [],
        "hostnames": sorted(hostnames),
        "country": geo.get("country") or reputation.get("country_name") or "",
        "country_code": geo.get("country_code") or reputation.get("country_code") or "",
        "city": geo.get("city") or "",
        "asn": geo.get("asn") or whois.get("asn") or privacy.get("asn_number"),
        "org": geo.get("org") or whois.get("asn_description") or privacy.get("company_name") or "",
        "network_cidr": geo.get("network_cidr") or whois.get("cidr") or whois.get("asn_cidr") or "",
        "abuse_contact": (whois.get("abuse_emails") or [None])[0]
        or reputation.get("domain")
        or privacy.get("abuse_contact_email")
        or "",
    }


# ── Main enrichment class ─────────────────────────────────────────────────────


class IPEnricher:
    def check_cache(self, ip: str) -> dict | None:
        try:
            with _pg_conn() as conn:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    cur.execute(
                        "SELECT data FROM ip_enrichment_cache WHERE ip = %s AND expires_at > NOW()",
                        (ip,),
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
                        (ip, json.dumps(data, default=str), expires),
                    )
                conn.commit()
        except Exception as e:
            log.warning(f"Cache write failed for {ip}: {e}")

    def enrich(self, ip: str) -> dict:
        if _is_private(ip):
            classification = _classify_private_ip(ip)
            return {"ip": ip, "private": True, **classification}

        cached = self.check_cache(ip)
        if cached:
            log.debug(f"Cache hit for {ip}")
            return cached

        log.info(f"Enriching {ip} ...")

        geo = _geoip_lookup(ip)
        privacy = _iplocate_lookup(ip)
        reputation = _abuseipdb_lookup(ip)
        infrastructure = _shodan_lookup(ip)
        whois = _whois_lookup(ip)
        dns = _reverse_dns(ip)
        threat_summary = _build_threat_summary(geo, privacy, reputation, infrastructure, whois, dns)

        sources_used = [
            name
            for name, val in (
                ("geoip", geo),
                ("iplocate", privacy),
                ("abuseipdb", reputation),
                ("shodan", infrastructure),
                ("whois", whois),
                ("dns", dns),
            )
            if val
        ]

        result = {
            "ip": ip,
            "private": False,
            "geo": geo,
            "privacy": privacy,
            "reputation": reputation,
            "infrastructure": infrastructure,
            "whois": whois,
            "dns": dns,
            "threat_summary": threat_summary,
            "sources_used": sources_used,
            "enriched_at": _now_utc().isoformat(),
        }

        self.save_cache(ip, result)
        return result

    def enrich_batch(self, ips: list, max_workers: int | None = None) -> dict:
        import concurrent.futures

        if max_workers is None:
            max_workers = config.ENRICH_PARALLEL_WORKERS
        results = {}
        unique = list({ip for ip in ips if ip})
        log.info(f"Enriching batch of {len(unique)} unique IPs (parallel={max_workers}) ...")
        if not unique:
            return results
        # Warm quota cache in one DB round-trip so per-IP lookups stay O(1).
        _tracker.prefetch(["iplocate", "abuseipdb", "shodan", "shodan_host", "virustotal"])
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
            future_to_ip = {pool.submit(self.enrich, ip): ip for ip in unique}
            for fut in concurrent.futures.as_completed(future_to_ip):
                ip = future_to_ip[fut]
                try:
                    results[ip] = fut.result()
                except Exception as e:
                    log.warning(f"Enrichment failed for {ip}: {e}")
                    results[ip] = {}
        return results

    def enrich_from_es(self, es_client, hours_back: int = 24) -> dict:
        since = (_now_utc() - timedelta(hours=hours_back)).isoformat()
        query = {
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gte": since}}},
                        {"exists": {"field": "source.ip"}},
                    ]
                }
            },
            "aggs": {"unique_ips": {"terms": {"field": "source.ip.keyword", "size": 10000}}},
        }
        try:
            resp = es_client.search(index=config.ES_INDEX, body=query)
        except Exception as e:
            log.warning(f"ES search failed (no honeypot indices yet?): {e}")
            return {}
        buckets = resp.get("aggregations", {}).get("unique_ips", {}).get("buckets", [])
        ips = [b["key"] for b in buckets]
        log.info(f"Found {len(ips)} unique source IPs in the last {hours_back}h")
        return self.enrich_batch(ips)
