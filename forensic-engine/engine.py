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
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta, timezone

import config
import psycopg2
import psycopg2.extras
import smb_analyzer
from chain_of_custody import ChainOfCustody
from db.init_db import get_conn_params, init_schema, wait_for_postgres
from elasticsearch import Elasticsearch
from enricher import IPEnricher
from ioc_extractor import IOCExtractor
from mitre_mapper import MitreMapper
from profiler import AttackerProfiler
from risk_score import SCORE_VERSION, score_ip, score_session
from risk_thresholds import ALERT_INDEX_MIN
from timeline_builder import TimelineBuilder
from virustotal import VirusTotalScanner
from yara_scanner import YARAScanner

# ── Logging setup ──────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("engine")


# ── WhatsApp alert via Twilio ─────────────────────────────────────────────────
def _send_whatsapp_alert(ip: str, score: int) -> None:
    sid = os.environ.get("TWILIO_ACCOUNT_SID", "")
    token = os.environ.get("TWILIO_AUTH_TOKEN", "")
    from_ = os.environ.get("TWILIO_WA_NUMBER", "")
    to = os.environ.get("DEST_WA", "")

    if not all([sid, token, from_, to]):
        log.warning("Twilio env vars missing — WhatsApp alert skipped")
        return

    level = "CRITICAL" if score >= 80 else "HIGH"
    body = (
        f"⚠️ ForenHive ALERTE\n"
        f"IP : {ip}\n"
        f"Risk Score : {score}/100\n"
        f"Niveau : {level} — Vérification requise."
    )
    from twilio.rest import Client

    client = Client(sid, token)
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(
                client.messages.create,
                from_=f"whatsapp:{from_}",
                to=to,
                body=body,
            )
            msg = future.result(timeout=5)
        log.info(f"WhatsApp alert sent to {to} — SID: {msg.sid}")
    except Exception as e:
        log.warning(f"WhatsApp alert failed for {ip}: {e}")


def _now_utc():
    return datetime.now(UTC)


import db_pool  # noqa: E402  (import tardif intentionnel — db_pool initialisé après config)


def _pg_conn():
    return db_pool.pooled_conn()


# ══════════════════════════════════════════════════════════════════════════════
# ELASTICSEARCH QUERIES
# ══════════════════════════════════════════════════════════════════════════════


def _build_es_client() -> Elasticsearch:
    return Elasticsearch(
        f"http://{config.ES_HOST}:{config.ES_PORT}",
        request_timeout=30,
    )


def _query_distinct_scored_ips(hours_back: int) -> list:
    """Get distinct IPs that were scored in the time window from PG."""
    try:
        conn = _pg_conn()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            since = (_now_utc() - timedelta(hours=hours_back)).isoformat()
            cur.execute(
                """
                SELECT DISTINCT source_ip FROM forensic_sessions
                WHERE created_at >= %s AND source_ip IS NOT NULL
                ORDER BY source_ip
                """,
                (since,),
            )
            rows = cur.fetchall()
        conn.close()
        return [row["source_ip"] for row in rows] if rows else []
    except Exception as e:
        log.warning(f"Query distinct scored IPs failed: {e}")
        return []


def _query_cowrie_sessions(es: Elasticsearch, hours_back: int) -> list:
    """Fetch distinct Cowrie sessions aggregated with key forensic fields."""
    since = (_now_utc() - timedelta(hours=hours_back)).isoformat()
    query = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": since}}},
                    {"term": {"honeypot.type.keyword": "cowrie"}},
                    {"exists": {"field": "session.id"}},
                ]
            }
        },
        "aggs": {
            "by_session": {
                "terms": {"field": "session.id.keyword", "size": 5000},
                "aggs": {
                    "source_ip": {"terms": {"field": "source.ip.keyword", "size": 1}},
                    "dest_port": {"terms": {"field": "destination.port", "size": 1}},
                    "login_count": {"filter": {"prefix": {"event.id": "cowrie.login"}}},
                    "login_success": {"filter": {"prefix": {"event.id": "cowrie.login.success"}}},
                    "login_failed": {"filter": {"prefix": {"event.id": "cowrie.login.failed"}}},
                    "command_count": {"filter": {"prefix": {"event.id": "cowrie.command"}}},
                    "total_bytes": {"sum": {"field": "network.bytes"}},
                    "first_seen": {"min": {"field": "@timestamp"}},
                    "last_seen": {"max": {"field": "@timestamp"}},
                },
            }
        },
    }

    try:
        resp = es.search(index=config.ES_INDEX, body=query)
    except Exception as e:
        log.error(f"Cowrie session query failed: {e}")
        return []
    sessions = []
    for bucket in resp.get("aggregations", {}).get("by_session", {}).get("buckets", []):
        session_id = bucket["key"]
        source_ip = (bucket["source_ip"]["buckets"] or [{}])[0].get("key", "")
        dest_port = (bucket["dest_port"]["buckets"] or [{}])[0].get("key", 0)
        sessions.append(
            {
                "session_id": session_id,
                "honeypot_type": "cowrie",
                "source_ip": source_ip,
                "login_attempts": bucket["login_count"]["doc_count"],
                "success_count": bucket["login_success"]["doc_count"],
                "failed_count": bucket["login_failed"]["doc_count"],
                "command_count": bucket["command_count"]["doc_count"],
                "exfil_bytes": int(bucket["total_bytes"]["value"] or 0),
                "destination_port": dest_port,
                "started_at": bucket["first_seen"]["value_as_string"],
                "ended_at": bucket["last_seen"]["value_as_string"],
            }
        )
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
                    {"term": {"honeypot.type.keyword": "dionaea"}},
                    {"exists": {"field": "source.ip"}},
                ]
            }
        },
        "aggs": {
            "by_ip": {
                "terms": {"field": "source.ip.keyword", "size": 5000},
                "aggs": {
                    "dest_port": {"terms": {"field": "destination.port", "size": 1}},
                    "event_count": {"value_count": {"field": "@timestamp"}},
                    "total_bytes": {"sum": {"field": "network.bytes"}},
                    "first_seen": {"min": {"field": "@timestamp"}},
                    "last_seen": {"max": {"field": "@timestamp"}},
                },
            }
        },
    }
    try:
        resp = es.search(index=config.ES_INDEX, body=query)
    except Exception as e:
        log.error(f"Dionaea session query failed: {e}")
        return []

    sessions = []
    for bucket in resp.get("aggregations", {}).get("by_ip", {}).get("buckets", []):
        source_ip = bucket["key"]
        dest_port = (bucket["dest_port"]["buckets"] or [{}])[0].get("key", 0)
        sessions.append(
            {
                "session_id": f"dionaea-{source_ip}-{dest_port}",
                "honeypot_type": "dionaea",
                "source_ip": source_ip,
                "login_attempts": bucket["event_count"]["value"],
                "success_count": 0,
                "failed_count": 0,
                "command_count": 0,
                "exfil_bytes": int(bucket["total_bytes"]["value"] or 0),
                "destination_port": dest_port,
                "started_at": bucket["first_seen"]["value_as_string"],
                "ended_at": bucket["last_seen"]["value_as_string"],
            }
        )
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
                    {"term": {"honeypot.type.keyword": "galah"}},
                    {"exists": {"field": "source.ip"}},
                ]
            }
        },
        "aggs": {
            "by_ip": {
                "terms": {"field": "source.ip.keyword", "size": 5000},
                "aggs": {
                    "dest_port": {"terms": {"field": "destination.port", "size": 1}},
                    "event_count": {"value_count": {"field": "@timestamp"}},
                    "total_bytes": {"sum": {"field": "network.bytes"}},
                    "first_seen": {"min": {"field": "@timestamp"}},
                    "last_seen": {"max": {"field": "@timestamp"}},
                    "http_paths": {"terms": {"field": "url.path.keyword", "size": 20}},
                },
            }
        },
    }
    try:
        resp = es.search(index=config.ES_INDEX, body=query)
    except Exception as e:
        log.error(f"Galah session query failed: {e}")
        return []

    sessions = []
    for bucket in resp.get("aggregations", {}).get("by_ip", {}).get("buckets", []):
        source_ip = bucket["key"]
        dest_port = (bucket["dest_port"]["buckets"] or [{}])[0].get("key", 0)
        http_paths = [p["key"] for p in bucket.get("http_paths", {}).get("buckets", [])]
        sessions.append(
            {
                "session_id": f"galah-{source_ip}",
                "honeypot_type": "galah",
                "source_ip": source_ip,
                "login_attempts": bucket["event_count"]["value"],
                "success_count": 0,
                "failed_count": 0,
                "command_count": 0,
                "exfil_bytes": int(bucket["total_bytes"]["value"] or 0),
                "destination_port": dest_port,
                "started_at": bucket["first_seen"]["value_as_string"],
                "ended_at": bucket["last_seen"]["value_as_string"],
                "http_paths": http_paths,
            }
        )
    return sessions


def _query_cowrie_commands(es: Elasticsearch, session_id: str) -> list:
    """Fetch shell commands executed within a Cowrie session."""
    query = {
        "size": 50,
        "_source": ["event.original", "process.command_line"],
        "query": {
            "bool": {
                "filter": [
                    {"term": {"session.id.keyword": session_id}},
                    {"prefix": {"event.id": "cowrie.command"}},
                ]
            }
        },
        "sort": [{"@timestamp": "asc"}],
    }
    try:
        resp = es.search(index=config.ES_INDEX, body=query)
        commands = []
        for hit in resp["hits"]["hits"]:
            src = hit["_source"]
            cmd = src.get("process", {}).get("command_line") or src.get("event", {}).get(
                "original", ""
            )
            if cmd:
                commands.append(cmd)
        return commands
    except Exception:
        return []


def _query_cowrie_file_downloads(es: Elasticsearch, session_id: str) -> int:
    """Count cowrie.session.file_download events for a session (T1105 indicator)."""
    query = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"term": {"session.id.keyword": session_id}},
                    {"prefix": {"event.id": "cowrie.session.file_download"}},
                ]
            }
        },
    }
    try:
        resp = es.search(index=config.ES_INDEX, body=query)
        return int(resp.get("hits", {}).get("total", {}).get("value", 0))
    except Exception as e:
        log.debug(f"file_download count query failed for {session_id}: {e}")
        return 0


def _query_sha256_from_es(es: Elasticsearch, hours_back: int) -> list:
    """Get distinct SHA-256 hashes from Cowrie file downloads."""
    since = (_now_utc() - timedelta(hours=hours_back)).isoformat()
    query = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": since}}},
                    {"exists": {"field": "file.hash.sha256"}},
                ]
            }
        },
        "aggs": {"hashes": {"terms": {"field": "file.hash.sha256.keyword", "size": 1000}}},
    }
    try:
        resp = es.search(index=config.ES_INDEX, body=query)
    except Exception as e:
        log.error(f"SHA256 query failed: {e}")
        return []
    return [b["key"] for b in resp.get("aggregations", {}).get("hashes", {}).get("buckets", [])]


def _query_ip_to_sha256(es: Elasticsearch, hours_back: int) -> dict:
    """Build {source_ip: [sha256, ...]} mapping from download events."""
    since = (_now_utc() - timedelta(hours=hours_back)).isoformat()
    query = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": since}}},
                    {"exists": {"field": "file.hash.sha256"}},
                    {"exists": {"field": "source.ip"}},
                ]
            }
        },
        "aggs": {
            "by_ip": {
                "terms": {"field": "source.ip.keyword", "size": 10000},
                "aggs": {"hashes": {"terms": {"field": "file.hash.sha256.keyword", "size": 100}}},
            }
        },
    }
    try:
        resp = es.search(index=config.ES_INDEX, body=query)
    except Exception as e:
        log.error(f"IP→SHA256 query failed: {e}")
        return {}
    result = {}
    for bucket in resp.get("aggregations", {}).get("by_ip", {}).get("buckets", []):
        ip = bucket["key"]
        hashes = [h["key"] for h in bucket.get("hashes", {}).get("buckets", [])]
        result[ip] = hashes
    return result


def _query_ip_honeypot_types(es: Elasticsearch, hours_back: int) -> dict:
    """Return {source_ip: [honeypot_type, ...]} for all IPs."""
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
        "aggs": {
            "by_ip": {
                "terms": {"field": "source.ip.keyword", "size": 10000},
                "aggs": {
                    "honeypot_types": {"terms": {"field": "honeypot.type.keyword", "size": 10}}
                },
            }
        },
    }
    try:
        resp = es.search(index=config.ES_INDEX, body=query)
    except Exception as e:
        log.error(f"IP→honeypot_types query failed: {e}")
        return {}
    result = {}
    for b in resp.get("aggregations", {}).get("by_ip", {}).get("buckets", []):
        result[b["key"]] = [t["key"] for t in b.get("honeypot_types", {}).get("buckets", [])]
    return result


def _load_file_analysis_from_pg(hours_back: int = 168) -> dict:
    """Load file_analysis rows analyzed within the lookback window.

    Defaults to 7 days (168h) so a short engine run still gets a full week of
    file-analysis context. Filtering by analyzed_at avoids loading the entire
    historical table into memory once it grows past a few thousand entries.
    """
    results = {}
    try:
        with _pg_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT sha256, yara_matches, virustotal_result
                    FROM file_analysis
                    WHERE analyzed_at > NOW() - make_interval(hours => %s)
                    """,
                    (int(hours_back),),
                )
                for row in cur.fetchall():
                    sha256 = row["sha256"]
                    yara = row["yara_matches"] or []
                    yara_with_sev = [
                        {
                            "rule": m["rule"],
                            "severity": (m.get("meta") or {}).get("severity", "medium"),
                        }
                        for m in yara
                        if isinstance(m, dict) and "rule" in m
                    ]
                    vt = row["virustotal_result"] or {}
                    results[sha256] = {
                        "yara_matches": yara_with_sev,
                        "vt_malicious": int(vt.get("malicious", 0)),
                        "vt_family": vt.get("family", "") or "",
                        "vt_tags": vt.get("tags", []) or [],
                        "vt_names": vt.get("names", []) or [],
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
                      AND created_at > NOW() - make_interval(hours => %s)
                      AND risk_score >= 20
                    GROUP BY source_ip
                    """,
                    (int(hours_back),),
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
        end = datetime.fromisoformat(str(ended_at).replace("Z", "+00:00"))
        duration = max((end - start).total_seconds(), 0.0)
    except Exception:
        return {
            "session_duration_sec": 0.0,
            "attack_velocity": 0.0,
            "hour_local": -1,
            "is_off_hours": False,
        }

    velocity = (attempts / duration) if duration > 0 else 0.0
    tunis = timezone(timedelta(hours=1))  # Africa/Tunis = GMT+1
    try:
        hour_local = start.astimezone(tunis).hour
    except Exception:
        hour_local = -1
    off_hours = (hour_local >= 22) or (0 <= hour_local < 6)
    return {
        "session_duration_sec": duration,
        "attack_velocity": velocity,
        "hour_local": hour_local,
        "is_off_hours": off_hours,
    }


# ── Session persistence ──────────────────────────────────────────────────────

_SESSION_INSERT_SQL = """
INSERT INTO forensic_sessions
    (session_id, honeypot_type, source_ip, started_at, ended_at,
     risk_score, risk_level, confidence,
     mitre_techniques, enrichment_data, signal_breakdown,
     kill_chain_phase, kill_chain_stage,
     primary_technique, forensic_narrative,
     login_attempts, success_count, attack_velocity,
     score_version,
     created_at, updated_at)
VALUES %s
ON CONFLICT (session_id) DO UPDATE
    SET risk_score         = EXCLUDED.risk_score,
        risk_level         = EXCLUDED.risk_level,
        confidence         = EXCLUDED.confidence,
        enrichment_data    = EXCLUDED.enrichment_data,
        signal_breakdown   = EXCLUDED.signal_breakdown,
        mitre_techniques   = EXCLUDED.mitre_techniques,
        kill_chain_phase   = EXCLUDED.kill_chain_phase,
        kill_chain_stage   = EXCLUDED.kill_chain_stage,
        primary_technique  = EXCLUDED.primary_technique,
        forensic_narrative = EXCLUDED.forensic_narrative,
        login_attempts     = EXCLUDED.login_attempts,
        success_count      = EXCLUDED.success_count,
        attack_velocity    = EXCLUDED.attack_velocity,
        score_version      = EXCLUDED.score_version,
        updated_at         = NOW()
"""

_SESSION_ROW_TEMPLATE = "(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW(),NOW())"


def _session_row(session: dict) -> tuple:
    return (
        session["session_id"],
        session.get("honeypot_type"),
        session.get("source_ip"),
        session.get("started_at"),
        session.get("ended_at"),
        session.get("risk_score"),
        session.get("risk_level"),
        session.get("confidence"),
        json.dumps(session.get("mitre_techniques", [])),
        json.dumps(session.get("enrichment_data", {})),
        json.dumps(session.get("signal_breakdown", {})),
        session.get("kill_chain_phase"),
        session.get("kill_chain_stage"),
        session.get("primary_technique"),
        session.get("forensic_narrative"),
        session.get("login_attempts", 0),
        session.get("success_count", 0),
        session.get("attack_velocity", 0.0),
        session.get("score_version") or SCORE_VERSION,
    )


def _save_sessions_batch(sessions: list):
    """Bulk upsert sessions in one transaction. ~100x faster than per-row."""
    if not sessions:
        return
    rows = [_session_row(s) for s in sessions]
    try:
        with _pg_conn() as conn:
            with conn.cursor() as cur:
                psycopg2.extras.execute_values(
                    cur,
                    _SESSION_INSERT_SQL,
                    rows,
                    template=_SESSION_ROW_TEMPLATE,
                    page_size=200,
                )
            conn.commit()
    except Exception as e:
        log.warning(
            f"Batch save failed ({len(sessions)} sessions): {e}; falling back to per-row upsert"
        )
        for s in sessions:
            _save_session(s)


def _save_session(session: dict):
    """Single-session upsert. Prefer _save_sessions_batch() in hot loops."""
    try:
        with _pg_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    _SESSION_INSERT_SQL.replace("VALUES %s", "VALUES " + _SESSION_ROW_TEMPLATE),
                    _session_row(session),
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
        self.es = _build_es_client()
        self.enricher = IPEnricher()
        self.yara = YARAScanner()
        self.vt = VirusTotalScanner()
        self.mitre = MitreMapper(use_llm=True)
        self.timeline = TimelineBuilder(self.es, _pg_conn)
        self.ioc = IOCExtractor(_pg_conn)
        self.coc = ChainOfCustody(_pg_conn)
        self.profiler = AttackerProfiler(self.es, _pg_conn)

    # ── Phase 0: SMB analysis ─────────────────────────────────────────────────

    def run_smb_analysis(self, enrichment_cache: dict = None) -> int:
        """Extract Dionaea SQLite + Zeek NTLM data, build profiles, index to ES."""
        log.info("=== Phase 0: SMB Forensic Analysis (Dionaea SQLite + Zeek NTLM) ===")
        db_path = smb_analyzer.DIONAEA_DB
        if not os.path.exists(db_path):
            log.info(f"SMB analysis: Dionaea DB not found at {db_path} — skipping")
            return 0
        try:
            dionaea_data = smb_analyzer.extract_dionaea(db_path)
        except Exception as e:
            log.warning(f"SMB analysis: extraction failed — {e}")
            return 0

        if not dionaea_data:
            log.info("SMB analysis: no SMB connections found")
            return 0

        all_ips = set(dionaea_data.keys())
        ntlm_data = smb_analyzer.extract_zeek_ntlm(smb_analyzer.ZEEK_LOGS, all_ips)

        # Re-use enrichment already computed in Phase 1 (avoids double API calls)
        enrichments = enrichment_cache or {}

        profiles = [
            smb_analyzer.build_profile(
                ip,
                dionaea_data[ip],
                ntlm_data.get(ip, {}),
                enrichments.get(ip, {}),
            )
            for ip in all_ips
        ]
        smb_analyzer.index_profiles(self.es, profiles)
        log.info(f"SMB analysis complete: {len(profiles)} profiles indexed")
        return len(profiles)

    # ── Phase 7: LLM attacker profiling ──────────────────────────────────────

    def run_profiling(self, scored: list) -> int:
        """Profile high-risk IPs via Ollama/Mistral.

        Threshold and max-per-run are configurable via PROFILE_RISK_THRESHOLD and
        MAX_PROFILES_PER_RUN env vars (defaults: 60 and 5 respectively).
        """
        log.info("=== Phase 7: LLM Attacker Profiling ===")
        threshold = config.PROFILE_RISK_THRESHOLD
        max_profiles = config.MAX_PROFILES_PER_RUN
        high_risk_ips = list({ip for _, ip, score, _, _ in scored if score >= threshold})[
            :max_profiles
        ]

        if not high_risk_ips:
            log.info("Profiling: no high-risk IPs (score ≥ 60) this run")
            return 0

        profiler = AttackerProfiler(self.es, _pg_conn)
        count = 0
        for ip in high_risk_ips:
            try:
                profiler.profile_ip(ip)
                count += 1
            except Exception as e:
                log.warning(f"Profiling failed for {ip}: {e}")
        log.info(f"Profiling complete: {count}/{len(high_risk_ips)} profiles generated")
        return count

    # ── Phase 8: Alert evaluation ─────────────────────────────────────────────

    def run_alert_evaluation(self, scored: list) -> dict:
        """Index alerts for sessions with risk_score >= ALERT_INDEX_MIN into forenhive-alerts ES index."""
        log.info("Evaluating sessions for alerts...")
        alert_count = 0
        failed_count = 0

        for session_id, source_ip, risk_score, level, honeypot_type in scored:
            if risk_score < ALERT_INDEX_MIN:
                continue

            try:
                # Fetch enrichment from PostgreSQL
                enrich = {}
                attempts = 0
                mitre_raw = []
                try:
                    with _pg_conn() as conn:
                        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                            cur.execute(
                                "SELECT enrichment_data, mitre_techniques FROM forensic_sessions WHERE session_id = %s",
                                (session_id,),
                            )
                            row = cur.fetchone()
                            if row:
                                enrich = row["enrichment_data"] or {}
                                mitre_raw = row["mitre_techniques"] or []
                                if isinstance(mitre_raw, str):
                                    mitre_raw = json.loads(mitre_raw)
                except Exception as pg_err:
                    log.debug(f"PG lookup failed for {session_id}: {pg_err}")

                # Normalise MITRE tags to plain strings
                mitre_tags = []
                for t in mitre_raw if isinstance(mitre_raw, list) else []:
                    if isinstance(t, dict):
                        tid = t.get("id") or t.get("technique_id", "")
                        if tid:
                            mitre_tags.append(tid)
                    elif isinstance(t, str):
                        mitre_tags.append(t)

                # Geo / reputation fields
                geo = enrich.get("geo", {}) or {}
                reputation = enrich.get("reputation", {}) or {}
                threat = enrich.get("threat_summary", {}) or {}

                country = (
                    geo.get("country_code")
                    or reputation.get("country_code")
                    or enrich.get("attribution", {}).get("country_code")
                    or None
                )
                abuseipdb_score = int(reputation.get("abuse_score") or 0)

                yara_matches = enrich.get("yara_matches") or []
                yara_match = yara_matches[0] if yara_matches else None

                threat_type = threat.get("tier") or "suspicious_activity"

                alert_doc = {
                    "id": session_id,
                    "timestamp": datetime.now(UTC).isoformat(),
                    "severity": level.lower(),
                    "threat_type": threat_type,
                    "source_ip": source_ip,
                    "country": country,
                    "honeypot": honeypot_type,
                    "risk_score": int(risk_score),
                    "attempts": int(attempts),
                    "mitre_tags": mitre_tags,
                    "yara_match": yara_match,
                    "abuseipdb_score": abuseipdb_score,
                    "ioc_hash": None,
                    "tsa_timestamp": None,
                    "mistral_analysis": None,
                    "recipients": [],
                    "dispatched": False,
                    "dispatch_error": None,
                }

                self.es.index(index="forenhive-alerts", id=session_id, body=alert_doc)
                alert_count += 1
                log.info(
                    f"Alert fired for {source_ip} "
                    f"(session {session_id[:12]}..., score={risk_score})"
                )

                # WhatsApp / voice call via Twilio
                try:
                    _send_whatsapp_alert(source_ip, int(risk_score))
                except Exception as _wa_err:
                    log.warning(f"WhatsApp alert failed for {source_ip}: {_wa_err}")

            except Exception as e:
                log.warning(f"Alert fire failed for session {session_id}: {e}")
                failed_count += 1

        log.info(f"Alert evaluation complete: {alert_count} fired, {failed_count} failed")
        return {"fired": alert_count, "failed": failed_count}

    # ── Phase 9: Unified risk scoring ────────────────────────────────────────

    def _store_unified_risk_score(self, score_data: dict) -> None:
        """Upsert unified risk score into ip_risk_scores (keyed by source_ip)."""
        try:
            with psycopg2.connect(
                host=config.PG_HOST,
                database=config.PG_DB,
                user=config.PG_USER,
                password=config.PG_PASSWORD,
            ) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO ip_risk_scores (
                            source_ip,
                            risk_score, risk_level, confidence, active_signals,
                            signal_breakdown,
                            honeypots_hit, honeypot_count, honeypot_summary, sessions_count,
                            key_findings, recommendations,
                            enrichment_snapshot,
                            score_version,
                            scored_at, updated_at
                        ) VALUES (
                            %s::inet,
                            %s, %s, %s, %s,
                            %s,
                            %s, %s, %s, %s,
                            %s, %s,
                            %s,
                            %s,
                            NOW(), NOW()
                        )
                        ON CONFLICT (source_ip) DO UPDATE SET
                            risk_score          = EXCLUDED.risk_score,
                            risk_level          = EXCLUDED.risk_level,
                            confidence          = EXCLUDED.confidence,
                            active_signals      = EXCLUDED.active_signals,
                            signal_breakdown    = EXCLUDED.signal_breakdown,
                            honeypots_hit       = EXCLUDED.honeypots_hit,
                            honeypot_count      = EXCLUDED.honeypot_count,
                            honeypot_summary    = EXCLUDED.honeypot_summary,
                            sessions_count      = EXCLUDED.sessions_count,
                            key_findings        = EXCLUDED.key_findings,
                            recommendations     = EXCLUDED.recommendations,
                            enrichment_snapshot = EXCLUDED.enrichment_snapshot,
                            score_version       = EXCLUDED.score_version,
                            updated_at          = NOW()
                        """,
                        (
                            score_data["source_ip"],
                            score_data["risk_score"],
                            score_data["risk_level"],
                            score_data["confidence"],
                            score_data.get("active_signals", 0),
                            json.dumps(score_data.get("signal_breakdown", {})),
                            score_data.get("honeypots_hit", []),
                            score_data.get("honeypot_count", 0),
                            json.dumps(score_data.get("honeypot_summary", {})),
                            score_data.get("sessions_count", 0),
                            score_data.get("key_findings", []),
                            json.dumps(score_data.get("recommendations", [])),
                            json.dumps(score_data.get("enrichment_snapshot", {})),
                            score_data.get("score_version", SCORE_VERSION),
                        ),
                    )
                conn.commit()
            log.info(f"Stored unified risk score for {score_data['source_ip']}")
        except Exception as e:
            log.error(f"Failed to store unified risk score: {e}", exc_info=True)

    # ── Timeline build ────────────────────────────────────────────────────────

    def run_timeline_build(self, hours_back: int = 24):
        return self.timeline.build(hours_back)

    def run_ioc_extraction(self, hours_back: int = 24):
        return self.ioc.build(hours_back)

    def run_chain_of_custody(self):
        return self.coc.run()

    # ── SMB profile query ─────────────────────────────────────────────────────

    def _query_smb_profiles(self, source_ips: list) -> dict:
        """Fetch pre-computed SMB profiles from ES."""
        if not source_ips:
            return {}
        try:
            resp = self.es.mget(index="forenhive-smb-analysis", body={"ids": source_ips})
            profiles = {}
            for doc in resp.get("docs", []):
                if doc.get("found"):
                    src = doc["_source"]
                    smb = src.get("smb_activity", {})
                    ops = smb.get("dcerpc_operations", [])
                    profiles[doc["_id"]] = {
                        "smb_share_enum": smb.get("share_enumerated", False),
                        "epmapper_prescan": smb.get("epmapper_prescan", 0),
                        "exploit_cve": [o["advisory"] for o in ops if o.get("advisory")],
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

    def run_session_scoring(
        self, hours_back: int = 24, enrichment_cache: dict = None, vt_was_available: bool = True
    ):
        log.info(f"=== Phase 3: Session Scoring + MITRE (last {hours_back}h) ===")

        # Gather sessions + correlation data from ES in parallel (independent queries)
        with ThreadPoolExecutor(max_workers=6) as pool:
            f_cowrie = pool.submit(_query_cowrie_sessions, self.es, hours_back)
            f_dionaea = pool.submit(_query_dionaea_sessions, self.es, hours_back)
            f_galah = pool.submit(_query_galah_sessions, self.es, hours_back)
            f_ip_to_sha256 = pool.submit(_query_ip_to_sha256, self.es, hours_back)
            f_honeypot_types = pool.submit(_query_ip_honeypot_types, self.es, hours_back)
            f_file_analysis = pool.submit(_load_file_analysis_from_pg, max(hours_back, 168))
            cowrie_sessions = f_cowrie.result()
            dionaea_sessions = f_dionaea.result()
            galah_sessions = f_galah.result()
            ip_to_sha256 = f_ip_to_sha256.result()
            honeypot_types = f_honeypot_types.result()
            file_analysis = f_file_analysis.result()

        all_sessions = cowrie_sessions + dionaea_sessions + galah_sessions
        log.info(
            f"Sessions: Cowrie={len(cowrie_sessions)} "
            f"Dionaea={len(dionaea_sessions)} Galah={len(galah_sessions)} "
            f"Total={len(all_sessions)}"
        )

        enrichment_cache = enrichment_cache or {}

        log.info(
            f"File analysis: {len(file_analysis)} entries, {len(ip_to_sha256)} IPs with file hashes"
        )

        # Cross-correlation data (SMB depends on all_ips; recidivism uses PG)
        all_ips = list({s.get("source_ip") for s in all_sessions if s.get("source_ip")})
        with ThreadPoolExecutor(max_workers=2) as pool:
            f_smb = pool.submit(self._query_smb_profiles, all_ips)
            f_recidivism = pool.submit(_query_recidivism)
            smb_profiles = f_smb.result()
            recidivism = f_recidivism.result()
        log.info(
            f"SMB profiles: {len(smb_profiles)}, "
            f"Honeypot-type correlation: {len(honeypot_types)} IPs, "
            f"Recidivists: {len(recidivism)}"
        )

        scored = []
        sessions_to_save = []

        for session in all_sessions:
            source_ip = session.get("source_ip", "")
            enrich = enrichment_cache.get(source_ip, {})
            reputation = enrich.get("reputation", {})
            privacy = enrich.get("privacy", {})
            geo = enrich.get("geo", {})
            infra = enrich.get("infrastructure", {})
            whois = enrich.get("whois", {})
            dns = enrich.get("dns", {})
            threat = enrich.get("threat_summary", {})
            shodan_host = infra.get("host_detail") or {}

            # Classify private IPs
            is_private = enrich.get("private", False)
            network_class = enrich.get("network_class", "")
            private_risk = enrich.get("private_risk_level", "")

            if private_risk == "ignore":
                log.debug(f"Skipping internal infrastructure IP {source_ip} ({network_class})")
                continue

            # Aggregate YARA/VT signals across all files from this IP
            ip_hashes = ip_to_sha256.get(source_ip, [])
            yara_matches = []
            vt_malicious = 0
            vt_family = ""
            vt_tags = []
            vt_names = []
            vt_first_seen = ""
            ip_sha256_list = []
            for sha256 in ip_hashes:
                fa = file_analysis.get(sha256, {})
                if not fa:
                    continue
                ip_sha256_list.append(sha256)
                yara_matches.extend(fa.get("yara_matches", []))
                if fa.get("vt_malicious", 0) > vt_malicious:
                    vt_malicious = fa["vt_malicious"]
                    vt_family = fa.get("vt_family", "") or vt_family
                    vt_tags = fa.get("vt_tags", []) or vt_tags
                    vt_names = fa.get("vt_names", []) or vt_names
                    vt_first_seen = fa.get("vt_first_seen", "") or vt_first_seen
            yara_matches = list(set(yara_matches))

            if not vt_was_available and yara_matches:
                log.warning(
                    f"Session {session['session_id'][:12]} IP={source_ip}: "
                    f"YARA matched {yara_matches} but VT quota exhausted"
                )

            # Time metrics
            time_metrics = _compute_time_metrics(
                session.get("started_at"),
                session.get("ended_at"),
                int(session.get("login_attempts", 0)),
            )
            session.update(time_metrics)  # persist velocity/duration to PG via _save_session

            smb = smb_profiles.get(source_ip, {})
            session_data = {
                **session,
                # Reputation
                "abuse_score": reputation.get("abuse_score", 0),
                "abuse_total_reports": reputation.get("total_reports", 0),
                "abuse_distinct_users": reputation.get("distinct_users", 0),
                "abuse_last_reported": reputation.get("last_reported_at", ""),
                "abuse_categories": threat.get("attack_categories", []),
                "abuse_recent_comments": reputation.get("recent_comments", []),
                "abuse_usage_type": reputation.get("usage_type", ""),
                "geo_isp": reputation.get("isp", "") or privacy.get("company_name", "") or "",
                # Privacy / anonymization
                "is_tor": threat.get("is_tor", False),
                "is_vpn": threat.get("is_vpn", False),
                "is_proxy": threat.get("is_proxy", False),
                "is_hosting": privacy.get("is_hosting", False),
                "is_datacenter": threat.get("is_datacenter", False),
                "is_anonymized": threat.get("is_anonymized", False),
                "is_abuser_listed": threat.get("is_abuser_listed", False),
                "is_bogon": threat.get("is_bogon", False),
                # GeoIP / ASN
                "geo_country": geo.get("country", "") or "",
                "geo_country_code": geo.get("country_code", "")
                or reputation.get("country_code", "")
                or "",
                "geo_region": geo.get("region", "") or "",
                "geo_city": geo.get("city", "") or "",
                "geo_postal": geo.get("postal_code", "") or "",
                "geo_lat": geo.get("lat"),
                "geo_lon": geo.get("lon"),
                "geo_timezone": geo.get("timezone", "") or "",
                "geo_continent": geo.get("continent", "") or "",
                "geo_asn": geo.get("asn", 0) or whois.get("asn") or 0,
                "geo_org": geo.get("org", "") or whois.get("asn_description", "") or "",
                "network_cidr": threat.get("network_cidr", ""),
                "asn_route": privacy.get("asn_route", ""),
                "asn_type": privacy.get("asn_type", ""),
                "company_domain": privacy.get("company_domain", ""),
                "abuse_contact": threat.get("abuse_contact", ""),
                # DNS
                "ptr_hostname": dns.get("ptr", ""),
                "all_hostnames": threat.get("hostnames", []),
                # Whois
                "whois_network": whois.get("network_name", ""),
                "whois_registry": whois.get("asn_registry", ""),
                "whois_registration": whois.get("registration", ""),
                # Shodan / attacker infrastructure
                "shodan_vulns": infra.get("vulns", []) or [],
                "shodan_tags": infra.get("tags", []) or [],
                "shodan_open_ports": infra.get("open_ports", []) or [],
                "shodan_hostnames": infra.get("hostnames", []) or [],
                "shodan_cpes": infra.get("cpes", []) or [],
                "shodan_os": shodan_host.get("os", ""),
                "shodan_services": shodan_host.get("services", []),
                "shodan_last_update": shodan_host.get("last_update", ""),
                # Threat summary (derived)
                "threat_tier": threat.get("tier", ""),
                # Malware
                "yara_matches": yara_matches,
                "vt_malicious": vt_malicious,
                "vt_family": vt_family,
                "vt_tags": vt_tags,
                "vt_names": vt_names,
                "vt_first_seen": vt_first_seen,
                "sha256_hashes": ip_sha256_list,
                # Classification
                "is_private": is_private,
                "vt_available": vt_was_available,
                "network_class": network_class,
                # SMB
                "smb_share_enum": smb.get("smb_share_enum", False),
                "epmapper_prescan": smb.get("epmapper_prescan", 0),
                "exploit_cve": smb.get("exploit_cve", []),
                # Correlation
                "honeypot_types_hit": honeypot_types.get(source_ip, []),
                # Recidivism
                "previously_seen": source_ip in recidivism,
                "previous_sessions": recidivism.get(source_ip, 0),
                # Time metrics
                **time_metrics,
            }

            # ── Fetch behavioral data BEFORE scoring ────────────────────────────
            if session.get("honeypot_type") == "cowrie":
                session_data["commands"] = _query_cowrie_commands(self.es, session["session_id"])
                session_data["file_download_count"] = _query_cowrie_file_downloads(
                    self.es, session["session_id"]
                )
            else:
                session_data["commands"] = []
                session_data["file_download_count"] = 0

            # ── MITRE deterministic mapping (techniques feed the scorer) ────────
            from mitre_mapper import (
                KILL_CHAIN_LABELS,
                get_kill_chain_phase,
                get_kill_chain_stage_number,
                get_techniques_deterministic,
            )

            tech_ids = get_techniques_deterministic(session_data)
            kill_chain_phase = get_kill_chain_phase(tech_ids)
            kill_chain_stage = get_kill_chain_stage_number(kill_chain_phase)

            session_data["mitre_techniques"] = tech_ids
            session_data["kill_chain_phase"] = kill_chain_phase
            session_data["kill_chain_stage"] = kill_chain_stage

            # ── 9-signal risk scoring (v2.0.0) ──────────────────────────────────
            result = score_session(session_data)

            # ── LLM narrative (techniques already mapped above) ─────────────────
            mitre_full = self.mitre.narrative_for(session_data, tech_ids)
            mitre_techniques = mitre_full["techniques"]
            primary_technique = mitre_full["primary_technique"]
            forensic_narrative = mitre_full["forensic_narrative"]

            session["risk_score"] = result.risk_score
            session["risk_level"] = result.risk_level
            session["confidence"] = result.confidence
            session["signal_breakdown"] = result.signal_breakdown
            session["score_version"] = result.score_version
            session["mitre_techniques"] = tech_ids
            session["kill_chain_phase"] = kill_chain_phase
            session["kill_chain_stage"] = kill_chain_stage
            session["primary_technique"] = primary_technique
            session["forensic_narrative"] = forensic_narrative
            session["enrichment_data"] = {
                **enrich,
                "risk_level": result.risk_level,
                "confidence": result.confidence,
                "score_version": result.score_version,
                "signal_breakdown": result.signal_breakdown,
                "active_signals": result.active_signals,
                "command_count": session_data.get("command_count", 0),
                "file_download_count": session_data["file_download_count"],
                "exfil_bytes": session.get("exfil_bytes", 0),
                "mitre_techniques": mitre_techniques,
                "kill_chain_phase": kill_chain_phase,
                "kill_chain_stage": kill_chain_stage,
                "kill_chain_label": KILL_CHAIN_LABELS.get(kill_chain_phase, kill_chain_phase),
                "primary_technique": primary_technique,
                "forensic_narrative": forensic_narrative,
                "mapping_source": mitre_full.get("mapping_source", "deterministic"),
                "yara_matches": yara_matches,
                "vt_malicious": vt_malicious,
                "vt_family": vt_family,
                "vt_available": vt_was_available,
                # Persist new fields so Phase 9 can read them back
                "smb_share_enum": session_data.get("smb_share_enum", False),
                "epmapper_prescan": session_data.get("epmapper_prescan", 0),
                "exploit_cve": session_data.get("exploit_cve", []),
                "previously_seen": session_data.get("previously_seen", False),
                "previous_sessions": session_data.get("previous_sessions", 0),
                "shodan_vulns": session_data.get("shodan_vulns", []),
                "is_bogon": session_data.get("is_bogon", False),
                "geo_country_code": session_data.get("geo_country_code", ""),
                "destination_port": session_data.get("destination_port", 0),
            }

            sessions_to_save.append(session)
            scored.append(
                (
                    session["session_id"],
                    source_ip,
                    result.risk_score,
                    result.risk_level,
                    session.get("honeypot_type", ""),
                )
            )

            if result.risk_score >= 40:
                lm = result.signal_breakdown.get("lateral_movement", {}).get("points", 0) > 0
                flags = " [LATERAL]" if lm else ""
                if kill_chain_phase:
                    flags += f" [{kill_chain_phase}]"
                log.info(
                    f"[{result.risk_level}] {session.get('honeypot_type', '?'):7s} "
                    f"Session {session['session_id'][:12]}... "
                    f"IP={source_ip} score={result.risk_score}{flags}"
                )

        # Bulk upsert all scored sessions in one transaction.
        if sessions_to_save:
            log.info(f"Persisting {len(sessions_to_save)} sessions to PostgreSQL ...")
            _save_sessions_batch(sessions_to_save)

        return scored

    # ── Full analysis ─────────────────────────────────────────────────────────

    def run_full_analysis(self, hours_back: int = 24):
        start = time.time()
        log.info(f"{'=' * 60}")
        log.info(f"  ForenHive Full Forensic Analysis (last {hours_back}h)")
        log.info(f"{'=' * 60}")

        # Fail fast if Elasticsearch is unreachable — otherwise every query
        # silently returns [] and we'd score an empty corpus.
        try:
            if not self.es.ping():
                log.error("Elasticsearch ping returned False — aborting full analysis")
                return
        except Exception as e:
            log.error(f"Elasticsearch unreachable — aborting full analysis: {e}")
            return

        # Phase 1 — IP enrichment
        enrichment_cache = self.run_enrichment(hours_back)

        # Phase 0 — SMB forensic analysis (uses Phase 1 enrichment; must run
        #            before Phase 3 so _query_smb_profiles() finds data in ES)
        smb_count = self.run_smb_analysis(enrichment_cache)

        # Phase 2a — YARA scan + VT for Dionaea files
        self.run_yara_scan()

        # Phase 2b — VT for Cowrie downloads
        self.run_vt_from_es(hours_back)

        # Phase 3 — Session scoring + MITRE (all honeypots)
        vt_ok = not self.vt.is_quota_exhausted()
        scored = self.run_session_scoring(hours_back, enrichment_cache, vt_was_available=vt_ok)

        # Phase 4 — Per-IP unified timeline (Cowrie + Dionaea + Galah + Zeek)
        timeline_stats = self.run_timeline_build(hours_back)

        # Phase 5 — Extract structured IoCs from timeline events
        ioc_stats = self.run_ioc_extraction(hours_back)

        # Phase 6 — Seal new / re-scored forensic_sessions
        coc_stats = self.run_chain_of_custody()

        # Phase 7 — LLM behavioral profiling for high-risk IPs
        profiled = self.run_profiling(scored)

        # Phase 8 — Alert evaluation (fire alerts for high-risk sessions)
        log.info("=== Phase 8: Alert Evaluation ===")
        alert_stats = self.run_alert_evaluation(scored)

        # Phase 9 — Unified risk scoring (one score per IP across all honeypots)
        log.info("=== Phase 9: Unified Risk Scoring (All Honeypots) ===")
        unique_ips = list({src_ip for _, src_ip, _, _, _ in scored})
        unified_count = 0

        with _pg_conn() as conn:
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            for src_ip in unique_ips:
                try:
                    # Narrowed SELECT (audit fix P-2)
                    cur.execute(
                        """
                        SELECT honeypot_type, login_attempts, success_count,
                               attack_velocity, mitre_techniques, kill_chain_stage,
                               kill_chain_phase, enrichment_data, started_at
                        FROM forensic_sessions
                        WHERE source_ip = %s
                          AND started_at > NOW() - make_interval(hours => %s)
                          AND honeypot_type != 'unified'
                        ORDER BY started_at DESC
                    """,
                        (src_ip, hours_back),
                    )

                    sessions_for_ip = []
                    for row in cur.fetchall():
                        ed = row["enrichment_data"] or {}
                        if isinstance(ed, str):
                            import json as _json

                            ed = _json.loads(ed)
                        sessions_for_ip.append(
                            {
                                "honeypot_type": row["honeypot_type"],
                                "login_attempts": row["login_attempts"] or 0,
                                "success_count": row["success_count"] or 0,
                                "attack_velocity": row["attack_velocity"] or 0.0,
                                "command_count": ed.get("command_count", 0),
                                "exfil_bytes": ed.get("exfil_bytes", 0),
                                "file_download_count": ed.get("file_download_count", 0),
                                "mitre_techniques": row["mitre_techniques"] or [],
                                "kill_chain_stage": row["kill_chain_stage"] or 0,
                                "kill_chain_phase": row["kill_chain_phase"] or "",
                                "yara_matches": ed.get("yara_matches", []),
                                "vt_malicious": ed.get("vt_malicious", 0),
                                "vt_family": ed.get("vt_family", ""),
                                "smb_share_enum": ed.get("smb_share_enum", False),
                                "epmapper_prescan": ed.get("epmapper_prescan", 0),
                                "exploit_cve": ed.get("exploit_cve", []),
                                "previously_seen": ed.get("previously_seen", False),
                                "previous_sessions": ed.get("previous_sessions", 0),
                                "command_quality_tags": (
                                    ed.get("signal_breakdown", {})
                                    .get("compromise_depth", {})
                                    .get("evidence", {})
                                    .get("command_quality_tags", [])
                                ),
                            }
                        )

                    # Load enrichment once per IP (same connection)
                    cur.execute(
                        "SELECT data FROM ip_enrichment_cache WHERE ip = %s LIMIT 1", (src_ip,)
                    )
                    row = cur.fetchone()
                    enrichment = (row["data"] if row else {}) or {}
                    if isinstance(enrichment, str):
                        import json as _json

                        enrichment = _json.loads(enrichment)

                    unified = score_ip(src_ip, sessions_for_ip, enrichment)
                    log.info(
                        f"Unified score for {src_ip}: {unified.risk_score}/{unified.risk_level}"
                    )

                    hps = sorted({s["honeypot_type"] for s in sessions_for_ip})
                    self._store_unified_risk_score(
                        {
                            "source_ip": src_ip,
                            "risk_score": unified.risk_score,
                            "risk_level": unified.risk_level,
                            "confidence": unified.confidence,
                            "active_signals": unified.active_signals,
                            "signal_breakdown": unified.signal_breakdown,
                            "honeypots_hit": hps,
                            "honeypot_count": len(hps),
                            "honeypot_summary": {
                                hp: sum(1 for s in sessions_for_ip if s["honeypot_type"] == hp)
                                for hp in hps
                            },
                            "sessions_count": unified.sessions_aggregated or 0,
                            "key_findings": [],
                            "recommendations": [],
                            "enrichment_snapshot": {
                                "country": (enrichment.get("geo") or {}).get("country"),
                                "city": (enrichment.get("geo") or {}).get("city"),
                                "asn": (enrichment.get("geo") or {}).get("asn"),
                                "org": (enrichment.get("geo") or {}).get("org"),
                                "is_tor": (enrichment.get("privacy") or {}).get("is_tor", False),
                                "is_vpn": (enrichment.get("privacy") or {}).get("is_vpn", False),
                                "abuse_score": (enrichment.get("reputation") or {}).get(
                                    "abuse_score", 0
                                ),
                            },
                            "score_version": unified.score_version,
                        }
                    )
                    unified_count += 1
                except Exception as e:
                    log.warning(f"Unified scoring failed for {src_ip}: {e}")

        log.info(f"Unified scoring complete: {unified_count}/{len(unique_ips)} IPs scored")

        # ── Summary ───────────────────────────────────────────────────────────
        elapsed = time.time() - start
        log.info(f"{'=' * 60}")
        log.info("  Analysis Complete")
        log.info(f"{'=' * 60}")
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
            high = sum(1 for _, _, s, _, _ in scored if 60 <= s < 80)
            medium = sum(1 for _, _, s, _, _ in scored if 40 <= s < 60)
            low = sum(1 for _, _, s, _, _ in scored if 20 <= s < 40)
            info = sum(1 for _, _, s, _, _ in scored if s < 20)
            log.info(
                f"  Risk breakdown : CRITICAL={critical} HIGH={high} "
                f"MEDIUM={medium} LOW={low} INFO={info}"
            )
        log.info(
            f"  Timeline events: +{timeline_stats['inserted']} (seen: {timeline_stats['seen']})"
        )
        log.info(
            f"  IoCs extracted : {ioc_stats['extracted']} "
            f"(from {ioc_stats['rows_scanned']} timeline rows)"
        )
        log.info(f"  SMB profiles   : {smb_count}")
        log.info(
            f"  Custody sealed : {coc_stats['sealed']} session(s), "
            f"batch=#{coc_stats.get('batch_id')}, "
            f"TSA={coc_stats.get('tsa_status')}"
        )
        log.info(f"  LLM profiles   : {profiled}")
        log.info(
            f"  Alerts fired   : {alert_stats.get('fired', 0)} (failed: {alert_stats.get('failed', 0)})"
        )
        log.info(f"  Unified scores : {unified_count}/{len(unique_ips)} IPs")
        log.info(f"  Duration       : {elapsed:.1f}s")


# ── Entry point ───────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(description="ForenHive Forensic Engine")
    parser.add_argument("--hours", type=int, default=24, help="Hours to look back")
    parser.add_argument("--enrich-only", action="store_true", help="IP enrichment only")
    parser.add_argument("--yara-only", action="store_true", help="YARA scan only")
    parser.add_argument("--score-only", action="store_true", help="Scoring + MITRE only")
    parser.add_argument("--timeline-only", action="store_true", help="Build per-IP timeline only")
    parser.add_argument(
        "--ioc-only", action="store_true", help="Extract IoCs from existing timeline only"
    )
    parser.add_argument(
        "--coc-only", action="store_true", help="Seal unsealed sessions (chain of custody) only"
    )
    parser.add_argument("--smb-only", action="store_true", help="SMB forensic analysis only")
    parser.add_argument(
        "--profile-only", action="store_true", help="LLM profiling only (high-risk IPs)"
    )
    parser.add_argument("--init-db", action="store_true", help="Initialize PostgreSQL schema")
    parser.add_argument(
        "--quota-status", action="store_true", help="Print external-API quota status and exit"
    )
    parser.add_argument(
        "--quota-reset",
        metavar="API",
        help="Manually clear exhausted flag for API (virustotal|abuseipdb|iplocate|shodan)",
    )
    args = parser.parse_args()

    if args.init_db:
        params = get_conn_params()
        if wait_for_postgres(params):
            init_schema(params)
        sys.exit(0)

    if args.quota_status:
        from quota_tracker import get_tracker

        for row in get_tracker().status():
            mark = "EXHAUSTED" if row["exhausted"] else "ok"
            log.info(
                f"  {row['api_name']:12s} {mark:10s} reset_at={row['reset_at']} last_error={row['last_error']}"
            )
        sys.exit(0)

    if args.quota_reset:
        from quota_tracker import get_tracker

        get_tracker().reset(args.quota_reset)
        sys.exit(0)

    engine = ForensicEngine()

    if args.enrich_only:
        engine.run_enrichment(args.hours)
    elif args.yara_only:
        engine.run_yara_scan()
    elif args.score_only:
        engine.run_session_scoring(args.hours)
    elif args.timeline_only:
        engine.run_timeline_build(args.hours)
    elif args.ioc_only:
        engine.run_ioc_extraction(args.hours)
    elif args.coc_only:
        engine.run_chain_of_custody()
    elif args.smb_only:
        engine.run_smb_analysis()
    elif args.profile_only:
        scored = engine.run_session_scoring(args.hours)
        engine.run_profiling(scored)
    else:
        engine.run_full_analysis(args.hours)


if __name__ == "__main__":
    main()
