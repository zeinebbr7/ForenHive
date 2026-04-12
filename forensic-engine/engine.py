"""
ForenHive Forensic Engine — Main Orchestrator
Coordinates all 4 analysis phases:

  1. IP Enrichment   : GeoIP, AbuseIPDB, Shodan InternetDB, Whois, Tor/VPN
  2. YARA Scan       : Dionaea captured malware binaries
  3. VirusTotal      : SHA-256 lookup for YARA-matched + Cowrie-downloaded files
  4. Session Scoring : risk score (0-100) + deterministic MITRE mapping
                       + LLM-based MITRE enrichment via Ollama/Mistral 7B

Multi-honeypot support: Cowrie (SSH/Telnet), Dionaea (SMB/services), Galah (HTTP)

Usage:
  python engine.py                      # full analysis (last 24h)
  python engine.py --hours 48           # look back 48 hours
  python engine.py --enrich-only        # IP enrichment only
  python engine.py --yara-only          # YARA scan only
  python engine.py --score-only         # scoring + MITRE only (skip enrichment/YARA)
  python engine.py --init-db            # initialize PostgreSQL schema
"""

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone, timedelta

import psycopg2
import psycopg2.extras
import requests
from elasticsearch import Elasticsearch

import config
from db.init_db import init_schema, wait_for_postgres, get_conn_params
from enricher import IPEnricher
from yara_scanner import YARAScanner
from virustotal import VirusTotalScanner
from risk_score import calculate_risk_score, risk_level
from mitre_mapper import MitreMapper

# ── Logging setup ──────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
    handlers=[logging.StreamHandler(sys.stdout)]
)
log = logging.getLogger("engine")


def _now_utc():
    return datetime.now(timezone.utc)


def _pg_conn():
    return psycopg2.connect(
        host=config.PG_HOST, port=config.PG_PORT,
        dbname=config.PG_DB, user=config.PG_USER,
        password=os.environ.get("PG_PASSWORD") or os.environ.get("POSTGRES_PASSWORD", "")
    )


# ══════════════════════════════════════════════════════════════════════════════
# ELASTICSEARCH QUERIES
# ══════════════════════════════════════════════════════════════════════════════

def _build_es_client() -> Elasticsearch:
    return Elasticsearch(
        [{"host": config.ES_HOST, "port": config.ES_PORT, "scheme": "http"}],
        request_timeout=30
    )


def _query_cowrie_sessions(es: Elasticsearch, hours_back: int) -> list:
    """Fetch distinct Cowrie sessions aggregated with key forensic fields."""
    since = (_now_utc() - timedelta(hours=hours_back)).isoformat()
    query = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": since}}},
                    {"term":  {"honeypot.type.keyword": "cowrie"}},
                    {"exists": {"field": "session.id"}}
                ]
            }
        },
        "aggs": {
            "by_session": {
                "terms": {"field": "session.id.keyword", "size": 5000},
                "aggs": {
                    "source_ip":     {"terms": {"field": "source.ip.keyword",     "size": 1}},
                    "dest_port":     {"terms": {"field": "destination.port", "size": 1}},
                    "login_count":   {"filter": {"prefix": {"event.id": "cowrie.login"}}},
                    "login_success": {"filter": {"prefix": {"event.id": "cowrie.login.success"}}},
                    "login_failed":  {"filter": {"prefix": {"event.id": "cowrie.login.failed"}}},
                    "command_count": {"filter": {"prefix": {"event.id": "cowrie.command"}}},
                    "total_bytes":   {"sum":    {"field": "network.bytes"}},
                    "first_seen":    {"min":    {"field": "@timestamp"}},
                    "last_seen":     {"max":    {"field": "@timestamp"}},
                }
            }
        }
    }

    resp = es.search(index=config.ES_INDEX, body=query)
    sessions = []
    for bucket in resp["aggregations"]["by_session"]["buckets"]:
        session_id = bucket["key"]
        source_ip  = (bucket["source_ip"]["buckets"] or [{}])[0].get("key", "")
        dest_port  = (bucket["dest_port"]["buckets"] or [{}])[0].get("key", 0)
        sessions.append({
            "session_id":     session_id,
            "honeypot_type":  "cowrie",
            "source_ip":      source_ip,
            "login_attempts": bucket["login_count"]["doc_count"],
            "success_count":  bucket["login_success"]["doc_count"],
            "failed_count":   bucket["login_failed"]["doc_count"],
            "command_count":  bucket["command_count"]["doc_count"],
            "exfil_bytes":    int(bucket["total_bytes"]["value"] or 0),
            "destination_port": dest_port,
            "started_at":     bucket["first_seen"]["value_as_string"],
            "ended_at":       bucket["last_seen"]["value_as_string"],
        })
    return sessions


def _query_dionaea_sessions(es: Elasticsearch, hours_back: int) -> list:
    """Fetch Dionaea connection events aggregated by source IP + destination port."""
    since = (_now_utc() - timedelta(hours=hours_back)).isoformat()
    query = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": since}}},
                    {"term":  {"honeypot.type.keyword": "dionaea"}},
                    {"exists": {"field": "source.ip"}}
                ]
            }
        },
        "aggs": {
            "by_ip": {
                "terms": {"field": "source.ip.keyword", "size": 5000},
                "aggs": {
                    "dest_port":   {"terms": {"field": "destination.port", "size": 1}},
                    "event_count": {"value_count": {"field": "@timestamp"}},
                    "total_bytes": {"sum": {"field": "network.bytes"}},
                    "first_seen":  {"min": {"field": "@timestamp"}},
                    "last_seen":   {"max": {"field": "@timestamp"}},
                }
            }
        }
    }
    try:
        resp = es.search(index=config.ES_INDEX, body=query)
    except Exception as e:
        log.warning(f"Dionaea session query failed: {e}")
        return []

    sessions = []
    for bucket in resp["aggregations"]["by_ip"]["buckets"]:
        source_ip = bucket["key"]
        dest_port = (bucket["dest_port"]["buckets"] or [{}])[0].get("key", 0)
        sessions.append({
            "session_id":       f"dionaea-{source_ip}-{dest_port}",
            "honeypot_type":    "dionaea",
            "source_ip":        source_ip,
            "login_attempts":   bucket["event_count"]["value"],
            "success_count":    0,
            "failed_count":     0,
            "command_count":    0,
            "exfil_bytes":      int(bucket["total_bytes"]["value"] or 0),
            "destination_port": dest_port,
            "started_at":       bucket["first_seen"]["value_as_string"],
            "ended_at":         bucket["last_seen"]["value_as_string"],
        })
    return sessions


def _query_galah_sessions(es: Elasticsearch, hours_back: int) -> list:
    """Fetch Galah (HTTP honeypot) events aggregated by source IP."""
    since = (_now_utc() - timedelta(hours=hours_back)).isoformat()
    query = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": since}}},
                    {"term":  {"honeypot.type.keyword": "galah"}},
                    {"exists": {"field": "source.ip"}}
                ]
            }
        },
        "aggs": {
            "by_ip": {
                "terms": {"field": "source.ip.keyword", "size": 5000},
                "aggs": {
                    "dest_port":   {"terms": {"field": "destination.port", "size": 1}},
                    "event_count": {"value_count": {"field": "@timestamp"}},
                    "total_bytes": {"sum": {"field": "network.bytes"}},
                    "first_seen":  {"min": {"field": "@timestamp"}},
                    "last_seen":   {"max": {"field": "@timestamp"}},
                    "http_paths":  {"terms": {"field": "url.path.keyword", "size": 20}},
                }
            }
        }
    }
    try:
        resp = es.search(index=config.ES_INDEX, body=query)
    except Exception as e:
        log.warning(f"Galah session query failed: {e}")
        return []

    sessions = []
    for bucket in resp["aggregations"]["by_ip"]["buckets"]:
        source_ip  = bucket["key"]
        dest_port  = (bucket["dest_port"]["buckets"] or [{}])[0].get("key", 0)
        http_paths = [p["key"] for p in bucket.get("http_paths", {}).get("buckets", [])]
        sessions.append({
            "session_id":       f"galah-{source_ip}",
            "honeypot_type":    "galah",
            "source_ip":        source_ip,
            "login_attempts":   bucket["event_count"]["value"],
            "success_count":    0,
            "failed_count":     0,
            "command_count":    0,
            "exfil_bytes":      int(bucket["total_bytes"]["value"] or 0),
            "destination_port": dest_port,
            "started_at":       bucket["first_seen"]["value_as_string"],
            "ended_at":         bucket["last_seen"]["value_as_string"],
            "http_paths":       http_paths,
        })
    return sessions


def _query_cowrie_commands(es: Elasticsearch, session_id: str) -> list:
    """Fetch shell commands executed within a Cowrie session."""
    query = {
        "size": 50,
        "_source": ["event.original", "process.command_line"],
        "query": {
            "bool": {
                "filter": [
                    {"term":   {"session.id.keyword": session_id}},
                    {"prefix": {"event.id": "cowrie.command"}}
                ]
            }
        },
        "sort": [{"@timestamp": "asc"}]
    }
    try:
        resp = es.search(index=config.ES_INDEX, body=query)
        commands = []
        for hit in resp["hits"]["hits"]:
            src = hit["_source"]
            cmd = src.get("process", {}).get("command_line") or src.get("event", {}).get("original", "")
            if cmd:
                commands.append(cmd)
        return commands
    except Exception:
        return []


def _query_sha256_from_es(es: Elasticsearch, hours_back: int) -> list:
    """Get distinct SHA-256 hashes from Cowrie file downloads."""
    since = (_now_utc() - timedelta(hours=hours_back)).isoformat()
    query = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": since}}},
                    {"exists": {"field": "file.hash.sha256"}}
                ]
            }
        },
        "aggs": {
            "hashes": {"terms": {"field": "file.hash.sha256.keyword", "size": 1000}}
        }
    }
    resp = es.search(index=config.ES_INDEX, body=query)
    return [b["key"] for b in resp["aggregations"]["hashes"]["buckets"]]


def _query_ip_to_sha256(es: Elasticsearch, hours_back: int) -> dict:
    """Build {source_ip: [sha256, ...]} mapping from download events."""
    since = (_now_utc() - timedelta(hours=hours_back)).isoformat()
    query = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"range":  {"@timestamp":      {"gte": since}}},
                    {"exists": {"field": "file.hash.sha256"}},
                    {"exists": {"field": "source.ip"}}
                ]
            }
        },
        "aggs": {
            "by_ip": {
                "terms": {"field": "source.ip.keyword", "size": 10000},
                "aggs": {
                    "hashes": {"terms": {"field": "file.hash.sha256.keyword", "size": 100}}
                }
            }
        }
    }
    resp = es.search(index=config.ES_INDEX, body=query)
    result = {}
    for bucket in resp["aggregations"]["by_ip"]["buckets"]:
        ip = bucket["key"]
        hashes = [h["key"] for h in bucket["hashes"]["buckets"]]
        result[ip] = hashes
    return result


def _query_ip_honeypot_types(es: Elasticsearch, hours_back: int) -> dict:
    """Return {source_ip: [honeypot_type, ...]} for all IPs."""
    since = (_now_utc() - timedelta(hours=hours_back)).isoformat()
    query = {
        "size": 0,
        "query": {"bool": {"filter": [
            {"range":  {"@timestamp": {"gte": since}}},
            {"exists": {"field": "source.ip"}},
        ]}},
        "aggs": {"by_ip": {
            "terms": {"field": "source.ip.keyword", "size": 10000},
            "aggs": {"honeypot_types": {"terms": {"field": "honeypot.type.keyword", "size": 10}}}
        }}
    }
    resp = es.search(index=config.ES_INDEX, body=query)
    result = {}
    for b in resp["aggregations"]["by_ip"]["buckets"]:
        result[b["key"]] = [t["key"] for t in b["honeypot_types"]["buckets"]]
    return result


def _load_file_analysis_from_pg() -> dict:
    """Load all file_analysis rows: sha256 → {yara_matches, vt_malicious, vt_family, ...}"""
    results = {}
    try:
        with _pg_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT sha256, yara_matches, virustotal_result FROM file_analysis")
                for row in cur.fetchall():
                    sha256 = row["sha256"]
                    yara = row["yara_matches"] or []
                    rule_names = [m["rule"] for m in yara if isinstance(m, dict) and "rule" in m]
                    vt = row["virustotal_result"] or {}
                    results[sha256] = {
                        "yara_matches":  rule_names,
                        "vt_malicious":  int(vt.get("malicious", 0)),
                        "vt_family":     vt.get("family", "") or "",
                        "vt_tags":       vt.get("tags", []) or [],
                        "vt_names":      vt.get("names", []) or [],
                        "vt_first_seen": vt.get("first_seen", "") or "",
                    }
    except Exception as e:
        log.warning(f"Could not load file_analysis from PostgreSQL: {e}")
    return results


def _query_recidivism(hours_back: int = 720) -> dict:
    """Return {source_ip: count_of_prior_sessions} for repeat offenders."""
    results = {}
    try:
        with _pg_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT source_ip, COUNT(*) AS prior
                    FROM forensic_sessions
                    WHERE created_at < NOW() - INTERVAL '1 hour'
                      AND created_at > NOW() - INTERVAL %s
                      AND risk_score >= 20
                    GROUP BY source_ip
                    """,
                    (f"{hours_back} hours",)
                )
                for row in cur.fetchall():
                    results[row[0]] = int(row[1])
    except Exception as e:
        log.warning(f"Recidivism query failed: {e}")
    return results


def _compute_time_metrics(started_at, ended_at, attempts: int) -> dict:
    """Derive duration, attack velocity, and off-hours flag."""
    try:
        start = datetime.fromisoformat(str(started_at).replace("Z", "+00:00"))
        end   = datetime.fromisoformat(str(ended_at).replace("Z", "+00:00"))
        duration = max((end - start).total_seconds(), 0.0)
    except Exception:
        return {"session_duration_sec": 0.0, "attack_velocity": 0.0,
                "hour_local": -1, "is_off_hours": False}

    velocity = (attempts / duration) if duration > 0 else 0.0
    tunis = timezone(timedelta(hours=1))  # Africa/Tunis = GMT+1
    try:
        hour_local = start.astimezone(tunis).hour
    except Exception:
        hour_local = -1
    off_hours = (hour_local >= 22) or (0 <= hour_local < 6)
    return {
        "session_duration_sec": duration,
        "attack_velocity":      velocity,
        "hour_local":           hour_local,
        "is_off_hours":         off_hours,
    }


# ── Session persistence ──────────────────────────────────────────────────────

def _save_session(session: dict):
    try:
        with _pg_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO forensic_sessions
                        (session_id, honeypot_type, source_ip, started_at, ended_at,
                         risk_score, mitre_techniques, enrichment_data,
                         kill_chain_phase, kill_chain_stage,
                         primary_technique, forensic_narrative,
                         created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
                    ON CONFLICT (session_id) DO UPDATE
                        SET risk_score         = EXCLUDED.risk_score,
                            enrichment_data    = EXCLUDED.enrichment_data,
                            mitre_techniques   = EXCLUDED.mitre_techniques,
                            kill_chain_phase   = EXCLUDED.kill_chain_phase,
                            kill_chain_stage   = EXCLUDED.kill_chain_stage,
                            primary_technique  = EXCLUDED.primary_technique,
                            forensic_narrative = EXCLUDED.forensic_narrative
                    """,
                    (
                        session["session_id"],
                        session.get("honeypot_type"),
                        session.get("source_ip"),
                        session.get("started_at"),
                        session.get("ended_at"),
                        session.get("risk_score"),
                        json.dumps(session.get("mitre_techniques", [])),
                        json.dumps(session.get("enrichment_data", {})),
                        session.get("kill_chain_phase"),
                        session.get("kill_chain_stage"),
                        session.get("primary_technique"),
                        session.get("forensic_narrative"),
                    )
                )
            conn.commit()
    except Exception as e:
        log.warning(f"Failed to save session {session['session_id']}: {e}")


# ══════════════════════════════════════════════════════════════════════════════
# FORENSIC ENGINE
# ══════════════════════════════════════════════════════════════════════════════

class ForensicEngine:

    def __init__(self):
        log.info("Initializing ForensicEngine ...")
        self.es       = _build_es_client()
        self.enricher = IPEnricher()
        self.yara     = YARAScanner()
        self.vt       = VirusTotalScanner()
        self.mitre    = MitreMapper(use_llm=True)

    # ── SMB profile query ─────────────────────────────────────────────────────

    def _query_smb_profiles(self, source_ips: list) -> dict:
        """Fetch pre-computed SMB profiles from ES."""
        if not source_ips:
            return {}
        try:
            resp = self.es.mget(index="forenhive-smb-analysis",
                                body={"ids": source_ips})
            profiles = {}
            for doc in resp.get("docs", []):
                if doc.get("found"):
                    src = doc["_source"]
                    smb = src.get("smb_activity", {})
                    ops = smb.get("dcerpc_operations", [])
                    profiles[doc["_id"]] = {
                        "smb_share_enum":   smb.get("share_enumerated", False),
                        "epmapper_prescan": smb.get("epmapper_prescan", 0),
                        "exploit_cve":      [o["advisory"] for o in ops if o.get("advisory")],
                    }
            return profiles
        except Exception as e:
            log.warning(f"SMB profile query failed: {e}")
            return {}

    # ── Phase 1: IP Enrichment ────────────────────────────────────────────────

    def run_enrichment(self, hours_back: int = 24) -> dict:
        log.info(f"=== Phase 1: IP Enrichment (last {hours_back}h) ===")
        results = self.enricher.enrich_from_es(self.es, hours_back)
        log.info(f"Enriched {len(results)} IPs")
        return results

    # ── Phase 2: YARA scan + VT ───────────────────────────────────────────────

    def run_yara_scan(self) -> list:
        log.info("=== Phase 2a: YARA Scan (Dionaea binaries) ===")
        scan_results = self.yara.scan_dionaea_downloads()
        if not scan_results:
            log.info("No Dionaea binary files found to scan")
            return []

        for entry in scan_results:
            if entry["matched"]:
                sha256 = entry["sha256"]
                log.info(f"VT lookup for {sha256[:16]}... (YARA match)")
                self.vt.lookup_hash(sha256)

        return scan_results

    def run_vt_from_es(self, hours_back: int = 24):
        log.info(f"=== Phase 2b: VirusTotal (Cowrie downloads, last {hours_back}h) ===")
        hashes = _query_sha256_from_es(self.es, hours_back)
        if not hashes:
            log.info("No SHA-256 hashes found in ES")
            return
        log.info(f"Found {len(hashes)} unique hashes — submitting to VirusTotal ...")
        self.vt.lookup_batch(hashes)

    # ── Phase 3: Session Scoring + MITRE ──────────────────────────────────────

    def run_session_scoring(self, hours_back: int = 24, enrichment_cache: dict = None,
                            vt_was_available: bool = True):
        log.info(f"=== Phase 3: Session Scoring + MITRE (last {hours_back}h) ===")

        # Gather sessions from ALL honeypots
        cowrie_sessions  = _query_cowrie_sessions(self.es, hours_back)
        dionaea_sessions = _query_dionaea_sessions(self.es, hours_back)
        galah_sessions   = _query_galah_sessions(self.es, hours_back)

        all_sessions = cowrie_sessions + dionaea_sessions + galah_sessions
        log.info(
            f"Sessions: Cowrie={len(cowrie_sessions)} "
            f"Dionaea={len(dionaea_sessions)} Galah={len(galah_sessions)} "
            f"Total={len(all_sessions)}"
        )

        enrichment_cache = enrichment_cache or {}

        # Load YARA/VT from PG and map to IPs via ES
        file_analysis   = _load_file_analysis_from_pg()
        ip_to_sha256    = _query_ip_to_sha256(self.es, hours_back)
        log.info(f"File analysis: {len(file_analysis)} entries, "
                 f"{len(ip_to_sha256)} IPs with file hashes")

        # Cross-correlation data
        all_ips = list({s.get("source_ip") for s in all_sessions if s.get("source_ip")})
        smb_profiles   = self._query_smb_profiles(all_ips)
        honeypot_types = _query_ip_honeypot_types(self.es, hours_back)
        recidivism     = _query_recidivism()
        log.info(f"SMB profiles: {len(smb_profiles)}, "
                 f"Honeypot-type correlation: {len(honeypot_types)} IPs, "
                 f"Recidivists: {len(recidivism)}")

        scored = []

        for session in all_sessions:
            source_ip  = session.get("source_ip", "")
            enrich     = enrichment_cache.get(source_ip, {})
            reputation = enrich.get("reputation", {})
            privacy    = enrich.get("privacy", {})
            geo        = enrich.get("geo", {})
            infra      = enrich.get("infrastructure", {})

            # Classify private IPs
            is_private    = enrich.get("private", False)
            network_class = enrich.get("network_class", "")
            private_risk  = enrich.get("private_risk_level", "")

            if private_risk == "ignore":
                log.debug(f"Skipping internal infrastructure IP {source_ip} ({network_class})")
                continue

            # Aggregate YARA/VT signals across all files from this IP
            ip_hashes       = ip_to_sha256.get(source_ip, [])
            yara_matches    = []
            vt_malicious    = 0
            vt_family       = ""
            vt_tags         = []
            vt_names        = []
            vt_first_seen   = ""
            ip_sha256_list  = []
            for sha256 in ip_hashes:
                fa = file_analysis.get(sha256, {})
                if not fa:
                    continue
                ip_sha256_list.append(sha256)
                yara_matches.extend(fa.get("yara_matches", []))
                if fa.get("vt_malicious", 0) > vt_malicious:
                    vt_malicious  = fa["vt_malicious"]
                    vt_family     = fa.get("vt_family", "") or vt_family
                    vt_tags       = fa.get("vt_tags", []) or vt_tags
                    vt_names      = fa.get("vt_names", []) or vt_names
                    vt_first_seen = fa.get("vt_first_seen", "") or vt_first_seen
            yara_matches = list(set(yara_matches))

            if not vt_was_available and yara_matches:
                log.warning(
                    f"Session {session['session_id'][:12]} IP={source_ip}: "
                    f"YARA matched {yara_matches} but VT quota exhausted"
                )

            # Time metrics
            time_metrics = _compute_time_metrics(
                session.get("started_at"), session.get("ended_at"),
                int(session.get("login_attempts", 0))
            )

            smb = smb_profiles.get(source_ip, {})
            session_data = {
                **session,
                # Reputation
                "abuse_score":         reputation.get("abuse_score", 0),
                "abuse_total_reports": reputation.get("total_reports", 0),
                "geo_isp":             reputation.get("isp", "") or "",
                # Privacy / anonymization
                "is_tor":              privacy.get("is_tor", False) or reputation.get("is_tor", False),
                "is_vpn":              privacy.get("is_vpn", False),
                "is_proxy":            privacy.get("is_proxy", False),
                "is_hosting":          privacy.get("is_hosting", False),
                # GeoIP / ASN
                "geo_country":         geo.get("country", "") or "",
                "geo_country_code":    geo.get("country_code", "") or reputation.get("country_code", "") or "",
                "geo_asn":             geo.get("asn", 0) or 0,
                "geo_org":             geo.get("org", "") or "",
                # Shodan / attacker infrastructure
                "shodan_vulns":        infra.get("vulns", []) or [],
                "shodan_tags":         infra.get("tags", []) or [],
                "shodan_open_ports":   infra.get("open_ports", []) or [],
                "shodan_hostnames":    infra.get("hostnames", []) or [],
                # Malware
                "yara_matches":        yara_matches,
                "vt_malicious":        vt_malicious,
                "vt_family":           vt_family,
                "vt_tags":             vt_tags,
                "vt_names":            vt_names,
                "vt_first_seen":       vt_first_seen,
                "sha256_hashes":       ip_sha256_list,
                # Classification
                "is_private":          is_private,
                "vt_available":        vt_was_available,
                "network_class":       network_class,
                # SMB
                "smb_share_enum":      smb.get("smb_share_enum", False),
                "epmapper_prescan":    smb.get("epmapper_prescan", 0),
                "exploit_cve":         smb.get("exploit_cve", []),
                # Correlation
                "honeypot_types_hit":  honeypot_types.get(source_ip, []),
                # Recidivism
                "previously_seen":     source_ip in recidivism,
                "previous_sessions":   recidivism.get(source_ip, 0),
                # Time metrics
                **time_metrics,
            }

            # ── Deterministic risk scoring (18 signals) ───────────────────────
            result = calculate_risk_score(session_data)
            score  = result["score"]
            level  = result["level"]

            # ── Hybrid MITRE mapping (deterministic IDs + LLM narrative) ────────
            if session.get("honeypot_type") == "cowrie":
                session_data["commands"] = _query_cowrie_commands(
                    self.es, session["session_id"]
                )

            mitre_result       = self.mitre.map_session(session_data)
            mitre_techniques   = mitre_result["techniques"]
            kill_chain_phase   = mitre_result["kill_chain_phase"]
            kill_chain_stage   = mitre_result["kill_chain_stage"]
            primary_technique  = mitre_result["primary_technique"]
            forensic_narrative = mitre_result["forensic_narrative"]

            session["risk_score"]         = score
            session["mitre_techniques"]   = [t["id"] for t in mitre_techniques
                                              if isinstance(t, dict)]
            session["kill_chain_phase"]   = kill_chain_phase
            session["kill_chain_stage"]   = kill_chain_stage
            session["primary_technique"]  = primary_technique
            session["forensic_narrative"] = forensic_narrative
            session["enrichment_data"]    = {
                **enrich,
                "risk_level":          level,
                "confidence":          result["confidence"],
                "attack_types":        result["attack_types"],
                "lateral_movement":    result["lateral_movement"],
                "signal_breakdown":    result["signal_breakdown"],
                "data_quality":        result["data_quality"],
                "notes":               result["notes"],
                "narrative":           result["narrative"],
                "recommended_actions": result["recommended_actions"],
                "iocs":                result["iocs"],
                "attribution":         result["attribution"],
                "mitre_techniques":    mitre_techniques,
                "kill_chain_phase":    kill_chain_phase,
                "kill_chain_stage":    kill_chain_stage,
                "kill_chain_label":    mitre_result["kill_chain_label"],
                "primary_technique":   primary_technique,
                "forensic_narrative":  forensic_narrative,
                "mapping_source":      mitre_result["mapping_source"],
            }

            _save_session(session)
            scored.append((session["session_id"], source_ip, score, level,
                           session.get("honeypot_type", "")))

            if score >= 40:
                flags = ""
                if result["lateral_movement"]:
                    flags += " [LATERAL]"
                if kill_chain_phase:
                    flags += f" [{kill_chain_phase}]"
                log.info(
                    f"[{level}] {session.get('honeypot_type','?'):7s} "
                    f"Session {session['session_id'][:12]}... "
                    f"IP={source_ip} score={score}{flags}"
                )

        return scored

    # ── Full analysis ─────────────────────────────────────────────────────────

    def run_full_analysis(self, hours_back: int = 24):
        start = time.time()
        log.info(f"{'='*60}")
        log.info(f"  ForenHive Full Forensic Analysis (last {hours_back}h)")
        log.info(f"{'='*60}")

        # Phase 1 — IP enrichment
        enrichment_cache = self.run_enrichment(hours_back)

        # Phase 2a — YARA scan + VT for Dionaea files
        self.run_yara_scan()

        # Phase 2b — VT for Cowrie downloads
        self.run_vt_from_es(hours_back)

        # Phase 3 — Session scoring + MITRE (all honeypots)
        vt_ok = not self.vt.is_quota_exhausted()
        scored = self.run_session_scoring(hours_back, enrichment_cache, vt_was_available=vt_ok)

        # ── Summary ───────────────────────────────────────────────────────────
        elapsed = time.time() - start
        log.info(f"{'='*60}")
        log.info(f"  Analysis Complete")
        log.info(f"{'='*60}")
        log.info(f"  IPs enriched   : {len(enrichment_cache)}")
        log.info(f"  Sessions scored: {len(scored)}")
        if scored:
            # Breakdown by honeypot type
            hp_counts = {}
            for _, _, _, _, hp in scored:
                hp_counts[hp] = hp_counts.get(hp, 0) + 1
            hp_str = ", ".join(f"{k}={v}" for k, v in sorted(hp_counts.items()))
            log.info(f"  By honeypot    : {hp_str}")

            critical = sum(1 for _, _, s, _, _ in scored if s >= 80)
            high     = sum(1 for _, _, s, _, _ in scored if 60 <= s < 80)
            medium   = sum(1 for _, _, s, _, _ in scored if 40 <= s < 60)
            low      = sum(1 for _, _, s, _, _ in scored if 20 <= s < 40)
            info     = sum(1 for _, _, s, _, _ in scored if s < 20)
            log.info(f"  Risk breakdown : CRITICAL={critical} HIGH={high} "
                     f"MEDIUM={medium} LOW={low} INFO={info}")
        log.info(f"  Duration       : {elapsed:.1f}s")


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="ForenHive Forensic Engine")
    parser.add_argument("--hours",       type=int, default=24, help="Hours to look back")
    parser.add_argument("--enrich-only", action="store_true",  help="IP enrichment only")
    parser.add_argument("--yara-only",   action="store_true",  help="YARA scan only")
    parser.add_argument("--score-only",  action="store_true",  help="Scoring + MITRE only")
    parser.add_argument("--init-db",     action="store_true",  help="Initialize PostgreSQL schema")
    args = parser.parse_args()

    if args.init_db:
        params = get_conn_params()
        if wait_for_postgres(params):
            init_schema(params)
        sys.exit(0)

    engine = ForensicEngine()

    if args.enrich_only:
        engine.run_enrichment(args.hours)
    elif args.yara_only:
        engine.run_yara_scan()
    elif args.score_only:
        engine.run_session_scoring(args.hours)
    else:
        engine.run_full_analysis(args.hours)


if __name__ == "__main__":
    main()
