from __future__ import annotations

import logging
from collections import Counter
from datetime import UTC, datetime
from typing import Any, Optional

from sqlalchemy import text

from db import session_scope
from models.report import AttackerProfile

from services.alert_engine import RiskScorer as _LegacyRiskScorer
from services.elasticsearch import get_es
from services.enrichment import get_enrichment
from services.ollama_service import get_ollama

log = logging.getLogger("profiler")


async def _unified_risk_for_ip(ip: str) -> Optional[dict]:
    """
    Read the 9-signal risk score for an IP from PostgreSQL.

    Lookup order (same source the PDF report uses, so the score on the
    platform always matches the PDF):
      1. ip_risk_scores  — per-IP aggregate over the sliding window
      2. forensic_sessions — most recent session for this IP (snapshot)

    Returns None if no row is found (engine has never scored this IP yet).
    """
    try:
        async with session_scope() as db:
            row = (await db.execute(
                text("""
                    SELECT risk_score, risk_level, confidence, signal_breakdown
                    FROM ip_risk_scores
                    WHERE source_ip = CAST(:ip AS INET)
                    LIMIT 1
                """),
                {"ip": ip},
            )).mappings().first()
            if row and row["risk_score"] is not None:
                return {
                    "risk_score":       int(row["risk_score"]),
                    "risk_level":       row["risk_level"],
                    "confidence":       row["confidence"],
                    "signal_breakdown": row["signal_breakdown"],
                    "risk_source":      "ip_risk_scores",
                }

            row = (await db.execute(
                text("""
                    SELECT risk_score, risk_level, confidence, signal_breakdown
                    FROM forensic_sessions
                    WHERE source_ip = :ip
                      AND honeypot_type != 'unified'
                    ORDER BY risk_score DESC NULLS LAST, started_at DESC
                    LIMIT 1
                """),
                {"ip": ip},
            )).mappings().first()
            if row and row["risk_score"] is not None:
                return {
                    "risk_score":       int(row["risk_score"]),
                    "risk_level":       row["risk_level"],
                    "confidence":       row["confidence"],
                    "signal_breakdown": row["signal_breakdown"],
                    "risk_source":      "forensic_sessions",
                }
    except Exception as e:
        log.warning(f"_unified_risk_for_ip({ip}) failed: {e}")
    return None


async def build_profile(ip: str) -> AttackerProfile:
    es = get_es()
    aggs = await es.profile_aggregates(ip)
    events = await es.events_for_ip(ip, size=200)

    def _first(bucket_name: str):
        b = aggs.get(bucket_name, {}).get("buckets", [])
        return b[0]["key"] if b else None

    def _list(bucket_name: str, limit: int = 10) -> list[str]:
        return [b["key"] for b in aggs.get(bucket_name, {}).get("buckets", [])][:limit]

    first_ts = aggs.get("first_seen", {}).get("value")
    last_ts = aggs.get("last_seen", {}).get("value")
    first_seen = datetime.fromtimestamp(first_ts / 1000, tz=UTC) if first_ts else None
    last_seen = datetime.fromtimestamp(last_ts / 1000, tz=UTC) if last_ts else None

    sessions: dict[str, dict[str, Any]] = {}
    commands_all: list[str] = []
    usernames_all: list[str] = []
    yara_matches: list[str] = []
    ioc_hashes: list[str] = []
    mitre: list[str] = []
    downloads: list[str] = []
    dest_ports: set = set()

    for e in events:
        sess_raw = e.get("session") or e.get("session_id")
        sid = (sess_raw.get("id") if isinstance(sess_raw, dict) else sess_raw) or None
        if sid:
            s = sessions.setdefault(sid, {"session_id": sid, "events": 0})
            s["events"] += 1
        cmd = e.get("input") or e.get("command") or (e.get("process") or {}).get("command_line")
        if cmd:
            commands_all.append(str(cmd))
        user_raw = e.get("user")
        user = (user_raw.get("name") if isinstance(user_raw, dict) else None) or e.get("username")
        if user:
            usernames_all.append(str(user))
        yara = e.get("yara_match")
        if yara:
            yara_matches.append(str(yara))
        f = e.get("file") or {}
        if isinstance(f, dict):
            sha = (f.get("hash") or {}).get("sha256") if isinstance(f.get("hash"), dict) else None
            if sha:
                ioc_hashes.append(sha)
        for t in (
            (e.get("mitre") or {}).get("technique", []) if isinstance(e.get("mitre"), dict) else []
        ):
            if isinstance(t, dict) and t.get("id"):
                mitre.append(t["id"])
        dp = (e.get("destination") or {}).get("port")
        if dp:
            dest_ports.add(int(dp))
        if e.get("eventid", "").startswith("cowrie.session.file"):
            url = e.get("url") or e.get("outfile")
            if url:
                downloads.append(str(url))

    honeypots = _list("honeypots", limit=10)

    enrichment = get_enrichment()
    iplocate = await enrichment.iplocate(ip)
    abuseipdb = await enrichment.abuseipdb(ip)

    country = iplocate.get("country") or _first("country")
    country_iso = iplocate.get("country_iso") or _first("country_iso")
    asn = iplocate.get("asn") or _first("asn")
    as_org = iplocate.get("as_org") or _first("as_org")

    top_commands = [c for c, _ in Counter(commands_all).most_common(10)]
    top_usernames = [u for u, _ in Counter(usernames_all).most_common(10)]

    # Single source of truth for the displayed risk score: the forensic engine's
    # 9-signal output stored in PostgreSQL (ip_risk_scores → forensic_sessions).
    # The legacy 18-signal alert_engine.RiskScorer is only used as a last-resort
    # fallback when the engine has never scored this IP yet.
    unified = await _unified_risk_for_ip(ip)
    if unified:
        risk_score       = unified["risk_score"]
        risk_level       = unified["risk_level"]
        risk_confidence  = unified["confidence"]
        signal_breakdown = unified["signal_breakdown"]
        risk_source      = unified["risk_source"]
    else:
        legacy_score, legacy_breakdown = _LegacyRiskScorer.score(
            {
                "failed_auth_count": sum(
                    1
                    for e in events
                    if e.get("eventid") == "cowrie.login.failed"
                    or (e.get("event") or {}).get("id") == "cowrie.login.failed"
                ),
                "is_tor": bool(iplocate.get("is_tor") or abuseipdb.get("is_tor")),
                "abuseipdb_score": abuseipdb.get("abuseipdb_score"),
                "yara_match": yara_matches[0] if yara_matches else None,
                "mitre_techniques": list(set(mitre)),
                "country_iso": country_iso,
                "new_ip": False,
                "payload": " ".join(top_commands),
                "commands": top_commands,
                "http_path": next(
                    (
                        e.get("url", {}).get("path") if isinstance(e.get("url"), dict) else None
                        for e in events
                    ),
                    None,
                ),
                "unique_dest_ports": len(dest_ports),
                "command_count": len(commands_all),
                "download_attempt": bool(downloads),
                "session_duration_seconds": 0,
            }
        )
        risk_score       = legacy_score
        risk_level       = None
        risk_confidence  = None
        signal_breakdown = None
        risk_source      = "legacy"
        log.info(f"build_profile({ip}): no engine score yet — using legacy estimate {legacy_score}/100")

    profile = AttackerProfile(
        ip=ip,
        first_seen=first_seen,
        last_seen=last_seen,
        event_count=int(aggs.get("total", {}).get("value", 0) or 0),
        session_count=int(aggs.get("sessions", {}).get("value", 0) or 0),
        honeypots=honeypots,
        country=country,
        country_iso=country_iso,
        city=iplocate.get("city") or _first("city"),
        asn=asn,
        as_org=as_org,
        is_tor=bool(iplocate.get("is_tor") or abuseipdb.get("is_tor")),
        is_vpn=bool(iplocate.get("is_vpn")),
        is_proxy=bool(iplocate.get("is_proxy")),
        abuseipdb_score=abuseipdb.get("abuseipdb_score"),
        abuseipdb_reports=abuseipdb.get("abuseipdb_reports"),
        usage_type=abuseipdb.get("usage_type"),
        isp=abuseipdb.get("isp"),
        domain=abuseipdb.get("domain"),
        mitre_techniques=sorted(set(mitre)),
        yara_matches=sorted(set(yara_matches)),
        ioc_hashes=sorted(set(ioc_hashes)),
        risk_score=risk_score,
        risk_level=risk_level,
        confidence=risk_confidence,
        signal_breakdown=signal_breakdown,
        risk_source=risk_source,
        top_usernames=top_usernames,
        top_passwords=_list("passwords"),
        top_commands=top_commands,
        recent_events=events[:25],
        sessions=list(sessions.values())[:25],
    )

    profile.mistral_analysis = await get_ollama().analyze_profile(profile.model_dump())
    return profile
