from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List

from models.report import AttackerProfile
from services.alert_engine import RiskScorer
from services.elasticsearch import get_es
from services.enrichment import get_enrichment
from services.ollama_service import get_ollama


async def build_profile(ip: str) -> AttackerProfile:
    es = get_es()
    aggs = await es.profile_aggregates(ip)
    events = await es.events_for_ip(ip, size=200)

    def _first(bucket_name: str):
        b = aggs.get(bucket_name, {}).get("buckets", [])
        return b[0]["key"] if b else None

    def _list(bucket_name: str, limit: int = 10) -> List[str]:
        return [b["key"] for b in aggs.get(bucket_name, {}).get("buckets", [])][:limit]

    first_ts = aggs.get("first_seen", {}).get("value")
    last_ts = aggs.get("last_seen", {}).get("value")
    first_seen = (
        datetime.fromtimestamp(first_ts / 1000, tz=timezone.utc) if first_ts else None
    )
    last_seen = (
        datetime.fromtimestamp(last_ts / 1000, tz=timezone.utc) if last_ts else None
    )

    sessions: Dict[str, Dict[str, Any]] = {}
    commands_all: List[str] = []
    usernames_all: List[str] = []
    yara_matches: List[str] = []
    ioc_hashes: List[str] = []
    mitre: List[str] = []
    downloads: List[str] = []
    dest_ports: set = set()

    for e in events:
        sid = e.get("session") or e.get("session_id")
        if sid:
            s = sessions.setdefault(sid, {"session_id": sid, "events": 0})
            s["events"] += 1
        cmd = e.get("input") or e.get("command")
        if cmd:
            commands_all.append(str(cmd))
        user = (e.get("user") or {}).get("name") or e.get("username")
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
        for t in (e.get("mitre") or {}).get("technique", []) if isinstance(e.get("mitre"), dict) else []:
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

    risk_score, _breakdown = RiskScorer.score(
        {
            "failed_auth_count": sum(
                1 for e in events if e.get("eventid") == "cowrie.login.failed"
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
                (e.get("url", {}).get("path") if isinstance(e.get("url"), dict) else None for e in events),
                None,
            ),
            "unique_dest_ports": len(dest_ports),
            "command_count": len(commands_all),
            "download_attempt": bool(downloads),
            "session_duration_seconds": 0,
        }
    )

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
        abuseipdb_score=abuseipdb.get("abuseipdb_score"),
        abuseipdb_reports=abuseipdb.get("abuseipdb_reports"),
        mitre_techniques=sorted(set(mitre)),
        yara_matches=sorted(set(yara_matches)),
        ioc_hashes=sorted(set(ioc_hashes)),
        risk_score=risk_score,
        top_usernames=top_usernames,
        top_passwords=_list("passwords"),
        top_commands=top_commands,
        recent_events=events[:25],
        sessions=list(sessions.values())[:25],
    )

    profile.mistral_analysis = await get_ollama().analyze_profile(profile.model_dump())
    return profile
