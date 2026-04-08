"""
ForenHive Forensic Engine — Main Orchestrator
Coordinates IP enrichment, YARA scanning, VirusTotal lookups,
risk scoring, and session persistence.

Usage:
  python engine.py                      # run full analysis (last 24h)
  python engine.py --hours 48           # look back 48 hours
  python engine.py --enrich-only        # IP enrichment only
  python engine.py --yara-only          # YARA scan only
  python engine.py --init-db            # initialize PostgreSQL schema
"""

import argparse
import json
import logging
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
        password=config.PG_PASSWORD
    )


# ── Elasticsearch helpers ──────────────────────────────────────────────────────

def _build_es_client() -> Elasticsearch:
    return Elasticsearch(
        [{"host": config.ES_HOST, "port": config.ES_PORT, "scheme": "http"}],
        request_timeout=30
    )


def _query_sessions(es: Elasticsearch, hours_back: int) -> list:
    """
    Fetch distinct Cowrie sessions from ES, aggregated with key forensic fields.
    Returns a list of session dicts.
    """
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
            "command_count":  bucket["command_count"]["doc_count"],
            "exfil_bytes":    int(bucket["total_bytes"]["value"] or 0),
            "destination_port": dest_port,
            "started_at":     bucket["first_seen"]["value_as_string"],
            "ended_at":       bucket["last_seen"]["value_as_string"],
        })
    return sessions


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
    """
    Build a mapping of source_ip → [sha256, ...] from Cowrie download events in ES.
    Used to link YARA/VT results from file_analysis to sessions by IP.
    """
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


def _load_file_analysis_from_pg() -> dict:
    """
    Load all file_analysis rows from PostgreSQL.
    Returns a dict: sha256 → {yara_matches: [...], vt_malicious: int}
    """
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
                    vt_malicious = int(vt.get("malicious", 0))
                    results[sha256] = {
                        "yara_matches": rule_names,
                        "vt_malicious": vt_malicious,
                    }
    except Exception as e:
        log.warning(f"Could not load file_analysis from PostgreSQL: {e}")
    return results


# ── Session persistence ────────────────────────────────────────────────────────

def _save_session(session: dict):
    try:
        with _pg_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO forensic_sessions
                        (session_id, honeypot_type, source_ip, started_at, ended_at,
                         risk_score, mitre_techniques, enrichment_data, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW())
                    ON CONFLICT (session_id) DO UPDATE
                        SET risk_score       = EXCLUDED.risk_score,
                            enrichment_data  = EXCLUDED.enrichment_data,
                            mitre_techniques = EXCLUDED.mitre_techniques
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
                    )
                )
            conn.commit()
    except Exception as e:
        log.warning(f"Failed to save session {session['session_id']}: {e}")


# ── ForensicEngine ─────────────────────────────────────────────────────────────

class ForensicEngine:

    def __init__(self):
        log.info("Initializing ForensicEngine ...")
        self.es       = _build_es_client()
        self.enricher = IPEnricher()
        self.yara     = YARAScanner()
        self.vt       = VirusTotalScanner()

    # ── Enrichment pass ────────────────────────────────────────────────────────

    def run_enrichment(self, hours_back: int = 24) -> dict:
        log.info(f"=== IP Enrichment (last {hours_back}h) ===")
        results = self.enricher.enrich_from_es(self.es, hours_back)
        log.info(f"Enriched {len(results)} IPs")
        return results

    # ── YARA + VT pass ─────────────────────────────────────────────────────────

    def run_yara_scan(self) -> list:
        log.info("=== YARA Scan (Dionaea binaries) ===")
        scan_results = self.yara.scan_dionaea_downloads()
        if not scan_results:
            log.info("No Dionaea binary files found to scan")
            return []

        # For each YARA match, also look up VirusTotal
        for entry in scan_results:
            if entry["matched"]:
                sha256 = entry["sha256"]
                log.info(f"VT lookup for {sha256[:16]}... (YARA match)")
                self.vt.lookup_hash(sha256)

        # Also check SHA-256 hashes from Cowrie downloads in ES
        return scan_results

    # ── SHA-256 VT pass (Cowrie downloads) ────────────────────────────────────

    def run_vt_from_es(self, hours_back: int = 24):
        log.info(f"=== VirusTotal lookup for Cowrie downloads (last {hours_back}h) ===")
        hashes = _query_sha256_from_es(self.es, hours_back)
        if not hashes:
            log.info("No SHA-256 hashes found in ES for the given period")
            return
        log.info(f"Found {len(hashes)} unique hashes — submitting to VirusTotal ...")
        self.vt.lookup_batch(hashes)

    # ── Session scoring pass ───────────────────────────────────────────────────

    def run_session_scoring(self, hours_back: int = 24, enrichment_cache: dict = None):
        log.info(f"=== Session Scoring (last {hours_back}h) ===")
        sessions = _query_sessions(self.es, hours_back)
        log.info(f"Found {len(sessions)} Cowrie sessions to score")

        enrichment_cache = enrichment_cache or {}

        # Load YARA/VT results from PostgreSQL and map them to source IPs via ES
        file_analysis   = _load_file_analysis_from_pg()
        ip_to_sha256    = _query_ip_to_sha256(self.es, hours_back)
        log.info(f"Loaded {len(file_analysis)} file_analysis entries, "
                 f"{len(ip_to_sha256)} IPs with file hashes")

        scored = []

        for session in sessions:
            source_ip  = session.get("source_ip", "")
            enrich     = enrichment_cache.get(source_ip, {})
            reputation = enrich.get("reputation", {})
            privacy    = enrich.get("privacy", {})

            # Aggregate YARA/VT signals across all files downloaded by this IP
            ip_hashes    = ip_to_sha256.get(source_ip, [])
            yara_matches = []
            vt_malicious = 0
            for sha256 in ip_hashes:
                fa = file_analysis.get(sha256, {})
                yara_matches.extend(fa.get("yara_matches", []))
                vt_malicious = max(vt_malicious, fa.get("vt_malicious", 0))
            yara_matches = list(set(yara_matches))  # deduplicate rule names

            session_data = {
                **session,
                "abuse_score":  reputation.get("abuse_score", 0),
                "is_tor":       privacy.get("is_tor", False),
                "is_vpn":       privacy.get("is_vpn", False),
                "is_proxy":     privacy.get("is_proxy", False),
                "yara_matches": yara_matches,
                "vt_malicious": vt_malicious,
            }

            score = calculate_risk_score(session_data)
            level = risk_level(score)

            session["risk_score"]      = score
            session["enrichment_data"] = enrich

            _save_session(session)
            scored.append((session["session_id"], source_ip, score, level))

            if score >= 40:
                log.info(
                    f"[{level}] Session {session['session_id'][:12]}... "
                    f"IP={source_ip} score={score}"
                )

        return scored

    # ── Full analysis ──────────────────────────────────────────────────────────

    def run_full_analysis(self, hours_back: int = 24):
        start = time.time()
        log.info(f"====== ForenHive Full Analysis (last {hours_back}h) ======")

        # 1 — IP enrichment
        enrichment_cache = self.run_enrichment(hours_back)

        # 2 — YARA scan + VT for Dionaea files
        self.run_yara_scan()

        # 3 — VT for Cowrie downloads
        self.run_vt_from_es(hours_back)

        # 4 — Session scoring
        scored = self.run_session_scoring(hours_back, enrichment_cache)

        # ── Summary ───────────────────────────────────────────────────────────
        elapsed = time.time() - start
        log.info("====== Analysis Complete ======")
        log.info(f"  IPs enriched  : {len(enrichment_cache)}")
        log.info(f"  Sessions scored: {len(scored)}")
        if scored:
            critical = sum(1 for _, _, s, _ in scored if s >= 80)
            high     = sum(1 for _, _, s, _ in scored if 60 <= s < 80)
            medium   = sum(1 for _, _, s, _ in scored if 40 <= s < 60)
            log.info(f"  Risk breakdown : CRITICAL={critical} HIGH={high} MEDIUM={medium}")
        log.info(f"  Duration       : {elapsed:.1f}s")


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="ForenHive Forensic Engine")
    parser.add_argument("--hours",       type=int, default=24, help="Hours to look back in ES")
    parser.add_argument("--enrich-only", action="store_true",  help="Run IP enrichment only")
    parser.add_argument("--yara-only",   action="store_true",  help="Run YARA scan only")
    parser.add_argument("--init-db",     action="store_true",  help="Initialize PostgreSQL schema and exit")
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
    else:
        engine.run_full_analysis(args.hours)


if __name__ == "__main__":
    main()
