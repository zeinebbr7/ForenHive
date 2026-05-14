import hashlib
import json
import logging
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from jinja2 import Environment, FileSystemLoader, select_autoescape
from slowapi import Limiter
from slowapi.util import get_remote_address

from config import get_settings
from models.report import (
    ReportListResponse,
    ReportMeta,
    ReportRequest,
    ReportScope,
)
from services.chain_custody import get_custody
from services.elasticsearch import get_es
from services.ollama_service import get_ollama
from services.profiler import build_profile
from services.report_service import get_reports

log = logging.getLogger(__name__)

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"

# MITRE ATT&CK technique → (name, tactic)
_MITRE_DB: Dict[str, tuple] = {
    "T1595":     ("Active Scanning",                    "Reconnaissance"),
    "T1595.001": ("Scanning IP Blocks",                 "Reconnaissance"),
    "T1590":     ("Gather Victim Network Info",          "Reconnaissance"),
    "T1589":     ("Gather Victim Identity Info",         "Reconnaissance"),
    "T1110":     ("Brute Force",                        "Credential Access"),
    "T1110.001": ("Brute Force: Password Guessing",     "Credential Access"),
    "T1110.003": ("Password Spraying",                  "Credential Access"),
    "T1078":     ("Valid Accounts",                     "Initial Access"),
    "T1059":     ("Command and Scripting Interpreter",  "Execution"),
    "T1059.004": ("Unix Shell",                         "Execution"),
    "T1552":     ("Unsecured Credentials",              "Credential Access"),
    "T1552.001": ("Credentials In Files",               "Credential Access"),
    "T1105":     ("Ingress Tool Transfer",              "Command & Control"),
    "T1046":     ("Network Service Discovery",          "Discovery"),
    "T1021":     ("Remote Services",                          "Lateral Movement"),
    "T1021.002": ("Remote Services: SMB/Windows Admin Shares", "Lateral Movement"),
    "T1021.004": ("Remote Services: SSH",                      "Lateral Movement"),
    "T1210":     ("Exploitation of Remote Services",           "Lateral Movement"),
    "T1547":     ("Boot or Logon Autostart Execution",  "Persistence"),
    "T1071":     ("Application Layer Protocol",         "Command & Control"),
    "T1027":     ("Obfuscated Files or Information",    "Defense Evasion"),
    "T1048":     ("Exfiltration Over Alternative Protocol", "Exfiltration"),
    "T1190":     ("Exploit Public-Facing Application",  "Initial Access"),
    "T1566":     ("Phishing",                           "Initial Access"),
    "T1003":     ("OS Credential Dumping",              "Credential Access"),
    "T1082":     ("System Information Discovery",       "Discovery"),
    "T1033":     ("System Owner/User Discovery",        "Discovery"),
}

_MONTHS_EN = ["", "January", "February", "March", "April", "May", "June",
              "July", "August", "September", "October", "November", "December"]

# YARA rule name → malware intelligence
_YARA_DB: Dict[str, Dict[str, str]] = {
    "mirai":      {"type": "Botnet",        "family": "Mirai",          "arch": "MIPS / ARM / x86",
                   "desc": "Linux botnet targeting IoT devices via Telnet/SSH brute-force. Enslaved hosts launch volumetric DDoS floods (UDP, SYN, ACK). First observed 2016; variants still dominant."},
    "hajime":     {"type": "Botnet",        "family": "Hajime",         "arch": "MIPS / ARM",
                   "desc": "Peer-to-peer IoT botnet using a BitTorrent-like DHT for C2. Competes with Mirai for the same attack surface."},
    "gafgyt":     {"type": "Botnet",        "family": "Gafgyt / BASHLITE", "arch": "MIPS / ARM",
                   "desc": "IoT botnet spread by Telnet brute-force. Launches UDP/TCP flood DDoS. Shares lineage with Mirai source code."},
    "tsunami":    {"type": "Backdoor",      "family": "Tsunami / Kaiten","arch": "x86 / MIPS",
                   "desc": "IRC-controlled DDoS bot targeting Linux servers. Provides a persistent backdoor and flood capabilities."},
    "wannacry":   {"type": "Ransomware",    "family": "WannaCry",       "arch": "x86 / x64",
                   "desc": "Self-propagating ransomware worm (May 2017) exploiting EternalBlue (CVE-2017-0144). Encrypts files with AES-128 and demands Bitcoin ransom."},
    "eternalblue":{"type": "Exploit",       "family": "EternalBlue",    "arch": "x86 / x64",
                   "desc": "NSA-developed SMBv1 exploit (CVE-2017-0144 / MS17-010). Used by WannaCry and NotPetya to achieve unauthenticated remote code execution."},
    "conficker":  {"type": "Worm",          "family": "Conficker",      "arch": "x86",
                   "desc": "Windows worm (2008) exploiting MS08-067. Spreads via network shares and removable drives; disables security services."},
    "xmrig":      {"type": "Cryptominer",   "family": "XMRig",          "arch": "x86 / x64 / ARM",
                   "desc": "Open-source Monero CPU/GPU miner repurposed for cryptojacking. Deployed after initial access to maximise resource abuse."},
    "cobalt":     {"type": "C2 Framework",  "family": "Cobalt Strike",  "arch": "x86 / x64",
                   "desc": "Commercial red-team framework abused as a post-exploitation RAT. Beacons exfiltrate data and accept tasking over HTTP/HTTPS."},
    "sliver":     {"type": "C2 Framework",  "family": "Sliver",         "arch": "x86 / x64 / ARM",
                   "desc": "Open-source adversary simulation framework (Go). Increasingly used as a Cobalt Strike alternative."},
    "emotet":     {"type": "Trojan Dropper","family": "Emotet",         "arch": "x86 / x64",
                   "desc": "Modular banking trojan / dropper. Delivered via malicious Office macros; downloads secondary payloads (TrickBot, QakBot)."},
    "meterpreter":{"type": "RAT / Payload", "family": "Metasploit Meterpreter","arch": "x86 / x64",
                   "desc": "In-memory post-exploitation payload from the Metasploit Framework. Provides interactive shell, keylogger, and pivoting capabilities."},
    "darkcomet":  {"type": "RAT",           "family": "DarkComet",      "arch": "x86",
                   "desc": "Remote Access Trojan (RAT) providing keylogging, webcam capture, file management, and reverse shell."},
    "nishang":    {"type": "PowerShell RAT","family": "Nishang",        "arch": "x64",
                   "desc": "Collection of offensive PowerShell scripts and payloads for post-exploitation on Windows."},
    "linuxback":  {"type": "Backdoor",      "family": "Linux Backdoor", "arch": "x86 / x64",
                   "desc": "Generic Linux backdoor maintaining persistent remote access; often dropped after initial Cowrie / Dionaea compromise."},
}


def _resolve_malware_info(yara_matches: List[str]) -> Dict[str, str]:
    """Return the first matching malware descriptor from _YARA_DB."""
    for rule in yara_matches:
        rl = rule.lower()
        for key, info in _YARA_DB.items():
            if key in rl:
                return info
    if yara_matches:
        return {"type": "Unknown", "family": yara_matches[0], "arch": "—",
                "desc": "No threat intelligence entry found for this YARA rule. Manual analysis recommended."}
    return {}

_RISK_LABEL_EN: Dict[str, str] = {
    "CRITIQUE": "CRITICAL",
    "ÉLEVÉ":    "HIGH",
    "MOYEN":    "MEDIUM",
    "FAIBLE":   "LOW",
    "INFO":     "INFO",
}

_KC_LABELS = ["Recon", "Weapon", "Delivery", "Exploit", "Install", "C2", "Lateral", "Actions"]
_KC_STAGES = ["reconnaissance", "weaponization", "delivery", "exploitation",
              "installation", "command_and_control", "lateral_movement", "actions_on_objectives"]


def _risk_label_color(score: int):
    if score >= 80: return "CRITIQUE", "#C62828"
    if score >= 60: return "ÉLEVÉ",    "#b36000"
    if score >= 40: return "MOYEN",    "#1565C0"
    if score >= 20: return "FAIBLE",   "#388E3C"
    return "INFO", "#757575"


def _mitre_lookup(tech_id: str):
    entry = _MITRE_DB.get(tech_id)
    if entry:
        return entry
    parent = tech_id[:5] if len(tech_id) > 5 else tech_id
    return _MITRE_DB.get(parent, (tech_id, "Unknown"))


_SIGNAL_META = {
    "reputation": {
        "name": "IP Reputation (AbuseIPDB)",
        "source": "AbuseIPDB",
        "why": "Community-reported abuse confidence. Scores ≥80 indicate confirmed malicious infrastructure. Max 25 pts.",
    },
    "compromise": {
        "name": "Compromise Confirmed (Auth Success)",
        "source": "Cowrie",
        "why": "Successful authentication grants interactive shell access — highest-severity signal. Max 25 pts.",
    },
    "brute_force": {
        "name": "Brute Force Automation",
        "source": "Cowrie / Dionaea",
        "why": "High-volume credential guessing (>200 attempts) or attack velocity >50 req/s. Max 20 pts.",
    },
    "malware": {
        "name": "Malware Detected (YARA / VirusTotal)",
        "source": "YARA Engine / VirusTotal",
        "why": "Binary captured by Dionaea matched a YARA rule or VirusTotal flagged ≥10 engines. Max 15 pts.",
    },
    "anonymization": {
        "name": "Anonymisation / Evasion (Tor / VPN)",
        "source": "IPLocate",
        "why": "Tor exit node (+10) or commercial VPN/proxy (+6). Indicates deliberate identity concealment. Max 10 pts.",
    },
    "sophistication": {
        "name": "Attack Sophistication (Multi-Honeypot)",
        "source": "ForenHive Correlator",
        "why": "+2 pts per additional honeypot type hit by the same IP. Max 5 pts.",
    },
}


def _build_score_signals_from_breakdown(breakdown: dict) -> List[dict]:
    """Build §07 signal list from the 6-signal JSONB stored by RiskScorer."""
    signals = []
    order = ["reputation", "compromise", "brute_force", "malware", "anonymization", "sophistication"]
    for key in order:
        sig = breakdown.get(key)
        if sig is None:
            continue
        meta = _SIGNAL_META.get(key, {"name": key, "source": "ForenHive", "why": ""})
        detail_txt = sig.get("detail") or ""
        signals.append({
            "name":   meta["name"],
            "source": meta["source"],
            "points": int(sig.get("points", 0)),
            "max":    int(sig.get("max", 0)),
            "value":  detail_txt,
            "why":    meta["why"],
        })
    return signals


def _build_score_signals_legacy(profile: dict, detail: dict) -> List[dict]:
    """Fallback: derive signals from profile + ES detail when no DB breakdown exists."""
    signals = []
    abuse = int(profile.get("abuseipdb_score") or 0)
    if abuse:
        pts = min(25, abuse * 25 // 100)
        signals.append({
            "name": "IP Reputation (AbuseIPDB)",
            "source": "AbuseIPDB",
            "points": pts, "max": 25,
            "value": f"{abuse}/100",
            "why": "Community-reported abuse confidence level (0–100). Scores ≥80 indicate confirmed malicious infrastructure.",
        })

    logins = detail.get("login_attempts") or []
    auth_success = any(a.get("success") for a in logins)
    if auth_success:
        signals.append({
            "name": "Compromise Confirmed (Auth Success)",
            "source": "Cowrie",
            "points": 25, "max": 25,
            "value": "Confirmed compromise",
            "why": "At least one authentication attempt succeeded. The attacker gained interactive shell access to the honeypot.",
        })

    yara = profile.get("yara_matches") or []
    if yara:
        signals.append({
            "name": "Malware Detected (YARA)",
            "source": "YARA Engine",
            "points": 15, "max": 15,
            "value": yara[0],
            "why": "Binary captured by Dionaea matched a YARA rule associated with a known malware family.",
        })

    if profile.get("is_tor"):
        signals.append({
            "name": "Tor Exit Node",
            "source": "IPLocate",
            "points": 10, "max": 10,
            "value": "YES — confirmed exit node",
            "why": "Source IP is a known Tor exit node. Anonymisation infrastructure indicates deliberate identity concealment.",
        })
    elif profile.get("is_vpn"):
        signals.append({
            "name": "VPN / Proxy Detected",
            "source": "IPLocate",
            "points": 6, "max": 10,
            "value": "YES",
            "why": "Source IP belongs to a commercial VPN or anonymising proxy service.",
        })

    return signals


def _adapt_context_for_v2(ctx: dict) -> dict:
    """Convert _build_forensic_context() output to forenhive_rapport_v2.html variables."""
    session = ctx.get("session", {})
    profile = ctx.get("profile", {})
    score   = ctx.get("risk_score", 0)

    risk_level = _RISK_LABEL_EN.get(ctx.get("risk_label", ""), "INFO")

    mitre_techniques = [
        {
            "tid":      r.get("id", ""),
            "name":     r.get("technique", ""),
            "tactic":   r.get("tactic", ""),
            "evidence": r.get("evidence", ""),
        }
        for r in ctx.get("mitre_rows", [])
    ]

    signal_breakdown = [
        {
            "name":       s.get("name", ""),
            "points":     s.get("points", 0),
            "max_points": s.get("max", 0),
            "value":      s.get("value", ""),
            "why":        s.get("why", ""),
        }
        for s in ctx.get("score_signals", [])
    ]

    all_timeline = [
        {
            "timestamp":  str(ev.get("ts", "")),
            "event_type": ev.get("action", ev.get("source", "")),
            "details":    ev.get("detail", ""),
            "mitre_tid":  ev.get("mitre") or None,
        }
        for ev in ctx.get("timeline", [])
    ]

    logins = session.get("login_attempts") or []
    auth_attempts = [
        {
            "username": a.get("username", ""),
            "password": a.get("password", ""),
            "success":  a.get("success", False),
        }
        for a in logins
    ]

    started_at = session.get("started_at", "")
    ended_at   = session.get("ended_at", "")
    duration   = session.get("duration_seconds", 0)
    duration_str = f"{duration:.1f}s" if isinstance(duration, (int, float)) and duration else "N/A"

    source_ip   = str(session.get("source_ip") or profile.get("ip") or "")
    event_count = len(all_timeline) or session.get("event_count", 0)

    malware_info   = ctx.get("malware_info") or {}
    malware_family = malware_info.get("family") if malware_info else None
    yara_matches   = profile.get("yara_matches") or []
    ioc_hashes     = profile.get("ioc_hashes") or []

    # IOCs: file hashes + any download URLs seen in commands
    iocs: List[Dict] = [
        {"type": "SHA-256", "value": h, "context": "File captured by Dionaea"}
        for h in ioc_hashes
    ]
    for cmd in (session.get("commands") or []):
        inp = cmd.get("input") or ""
        if any(x in inp for x in ["wget ", "curl "]):
            for part in inp.split():
                if part.startswith("http"):
                    iocs.append({"type": "URL", "value": part, "context": f"Download command: {inp[:60]}"})
                    break

    # Dropped files (one entry per captured binary)
    dropped_files: List[Dict] = []
    if ioc_hashes:
        vt = ctx.get("vt_result") or {}
        dropped_files.append({
            "filename":      profile.get("captured_file", "captured_file"),
            "sha256":        ioc_hashes[0],
            "yara_hits":     yara_matches,
            "vt_detections": vt.get("malicious") if vt else None,
            "vt_total":      vt.get("total") if vt else None,
        })

    # Chain of custody (session snapshot hash from existing context)
    chain_of_custody = [{
        "artifact":  "Session JSON snapshot",
        "sha256":    ctx.get("sha256_session", ""),
        "timestamp": str(started_at),
        "tsa":       "freetsa.org",
    }]

    # Verdict
    if score >= 80:
        verdict = f"Confirmed high-severity threat ({malware_family or 'malware deployment detected'})"
    elif score >= 60:
        verdict = f"Likely malicious activity — {malware_family or 'attack confirmed'}"
    elif score >= 40:
        verdict = "Suspicious activity requiring further investigation"
    else:
        verdict = "Low-risk activity — continued monitoring recommended"

    # Behavioral profile
    traits: List[str] = []
    if profile.get("is_tor"):
        traits.append("Uses Tor anonymization network")
    if profile.get("is_vpn"):
        traits.append("Uses commercial VPN or proxy service")
    if auth_attempts:
        traits.append(f"Credential brute-force ({len(auth_attempts)} attempts)")
    if yara_matches:
        traits.append(f"Deployed known malware ({', '.join(yara_matches[:2])})")
    if ctx.get("auth_success"):
        traits.append("Achieved initial access via valid credentials")

    org_pct = ctx.get("org_score_pct", 50)
    sophistication = "HIGH" if score >= 70 else ("MEDIUM" if score >= 40 else "LOW")
    profile_out = {
        "sophistication":    sophistication,
        "confidence":        org_pct,
        "objective":         malware_family or ("Credential harvesting" if auth_attempts else "Unknown"),
        "organized_score":   min(10, org_pct // 10),
        "behavioral_traits": traits,
        "detective_narrative": profile.get("mistral_analysis", ""),
        "es_reference_cases": [],
    }

    # Recommendations
    recommendations: List[Dict] = []
    if score >= 80:
        recommendations.append({
            "priority":  "IMMEDIATE",
            "action":    f"Block {source_ip} at perimeter firewall and upstream BGP if possible",
            "rationale": "Critical risk score with confirmed malicious activity",
        })
    if ctx.get("auth_success"):
        recommendations.append({
            "priority":  "IMMEDIATE",
            "action":    "Audit all systems for lateral movement originating from this IP",
            "rationale": "Attacker achieved successful authentication on the honeypot",
        })
    if yara_matches:
        recommendations.append({
            "priority":  "HIGH",
            "action":    "Submit captured binary to AV vendors and threat intelligence feeds",
            "rationale": f"YARA matched: {', '.join(yara_matches[:2])}",
        })
    if auth_attempts:
        recommendations.append({
            "priority":  "HIGH",
            "action":    "Enforce MFA and review credential policies on all internet-facing services",
            "rationale": f"{len(auth_attempts)} authentication attempts observed",
        })
    recommendations.append({
        "priority":  "MEDIUM",
        "action":    "Update SIEM detection rules with IOCs from this report",
        "rationale": "Integrate findings into the operational threat intelligence pipeline",
    })

    enrichment = ctx.get("enrichment_cache") or {}
    rep     = enrichment.get("reputation")     or {}
    whois   = enrichment.get("whois")          or {}
    privacy = enrichment.get("privacy")        or {}
    threat  = enrichment.get("threat_summary") or {}
    dns     = enrichment.get("dns")            or {}
    geo     = enrichment.get("geo")            or {}

    # Shodan: threat_summary aggregates open_ports / vulns / tags from Shodan InternetDB
    _shodan_ports = threat.get("open_ports") or []
    _shodan_vulns = threat.get("known_vulns") or []
    _shodan_tags  = threat.get("shodan_tags")  or []
    _shodan_hosts = list(dict.fromkeys(
        ([dns.get("ptr")] if dns.get("ptr") else []) +
        (threat.get("hostnames") or []) +
        (rep.get("hostnames") or [])
    ))
    shodan_data = {
        "ports":     _shodan_ports,
        "hostnames": _shodan_hosts,
        "vulns":     _shodan_vulns,
        "tags":      _shodan_tags,
    } if (_shodan_ports or _shodan_vulns or _shodan_tags or _shodan_hosts) else None

    return {
        # Cover
        "report_id":         ctx.get("report_ref", "FH-UNKNOWN"),
        "session_id":        ctx.get("session_id", ""),
        "generated_at":      ctx.get("generated_at_str", ""),
        "engine_version":    "3.1",
        "classification":    "TLP:AMBER",
        # Risk
        "risk_level":        risk_level,
        "risk_score":        score,
        "risk_confidence":   "HIGH" if score >= 70 else ("MEDIUM" if score >= 40 else "LOW"),
        "risk_warnings":     [],
        # Executive summary
        "verdict":           verdict,
        "source_ip":         source_ip,
        "session_date":      str(started_at)[:10] if started_at else "",
        "geo_country":       profile.get("country", "Unknown"),
        "geo_city":          profile.get("city", "Unknown"),
        "asn":               profile.get("asn", "Unknown"),
        "isp":               profile.get("isp", ""),
        "abuse_score":       profile.get("abuseipdb_score") or 0,
        "abuse_reports":     rep.get("total_reports", "N/A"),
        "event_count":       event_count,
        "honeypot_type":     (session.get("honeypot") or profile.get("honeypot", "Cowrie")).title(),
        "protocol":          session.get("protocol", "SSH"),
        "session_start":     str(started_at),
        "session_end":       str(ended_at),
        "session_duration":  duration_str,
        "auth_attempts":     auth_attempts,
        # MITRE
        "mitre_techniques":  mitre_techniques,
        "mitre_narrative":   profile.get("mistral_analysis", ""),
        # Malware
        "yara_matches":      yara_matches,
        "yara_rules_used":   10,
        "malware_family":    malware_family,
        "dropped_files":     dropped_files,
        # Risk signals
        "signal_breakdown":  signal_breakdown,
        # Timeline
        "timeline_summary":  all_timeline[:15],
        "full_timeline":     all_timeline,
        # Profile
        "profile":           profile_out,
        # IOCs
        "iocs":              iocs,
        "stix_export_path":  None,
        # Chain of custody
        "chain_of_custody":        chain_of_custody,
        "coc_timestamp_authority": "freetsa.org",
        # Shodan / WHOIS / IPLocate enrichment
        "shodan_data":  shodan_data,
        "whois_data":   whois,
        "iplocate_data": {
            "is_tor":       privacy.get("is_tor") or threat.get("is_tor", False),
            "is_vpn":       privacy.get("is_vpn") or threat.get("is_vpn", False),
            "is_proxy":     privacy.get("is_proxy", False),
            "is_hosting":   privacy.get("is_hosting", False),
            "is_datacenter":privacy.get("is_datacenter", False),
            "is_bogon":     privacy.get("is_bogon", False),
            "is_abuser":    privacy.get("is_abuser", False),
            "company_name": privacy.get("company_name", ""),
            "asn_name":     privacy.get("asn_name") or geo.get("org", ""),
            "asn_type":     privacy.get("asn_type", ""),
            "asn_number":   privacy.get("asn_number") or (f"AS{geo.get('asn')}" if geo.get("asn") else ""),
            "asn_domain":   privacy.get("asn_domain", ""),
        },
        "ptr_hostname": dns.get("ptr", ""),
        # Deterministic recommendations
        "recommendations":         recommendations,
        # Ollama recommendations (passed through from _build_forensic_context)
        "ollama_recommendations":  ctx.get("ollama_recommendations", []),
        # VirusTotal fields (fix: these were missing and caused "Quota épuisé" always)
        "vt_available": ctx.get("vt_available", True),
        "vt_malicious": ctx.get("vt_malicious", 0),
        "vt_family":    ctx.get("vt_family", ""),
        "extra_references":  [],
    }


async def _build_forensic_context(session_id: str) -> dict:
    from sqlalchemy import text
    from db import session_scope

    es = get_es()
    detail = await es.session_detail(session_id) or {}
    source_ip: Optional[str] = detail.get("source_ip")

    # ── Try PostgreSQL forensic_sessions first (forensic engine enriched data) ──
    pg_row: Dict[str, Any] = {}
    try:
        async with session_scope() as db:
            result = await db.execute(
                text("""
                    SELECT session_id, source_ip, honeypot_type, risk_score,
                           risk_level, confidence, signal_breakdown,
                           kill_chain_phase, kill_chain_stage, primary_technique,
                           forensic_narrative, mitre_techniques, started_at,
                           login_attempts, success_count, sessions_count, honeypots_hit
                    FROM forensic_sessions
                    WHERE session_id = :sid
                    LIMIT 1
                """),
                {"sid": session_id},
            )
            row = result.mappings().fetchone()
            if row:
                pg_row = dict(row)
                # Normalise mitre_techniques to list
                mt = pg_row.get("mitre_techniques") or []
                if isinstance(mt, str):
                    try:
                        mt = json.loads(mt)
                    except Exception:
                        mt = []
                pg_row["mitre_techniques"] = mt
                # Normalise signal_breakdown to dict
                sb = pg_row.get("signal_breakdown") or {}
                if isinstance(sb, str):
                    try:
                        sb = json.loads(sb)
                    except Exception:
                        sb = {}
                pg_row["signal_breakdown"] = sb
                # Fill detail gaps from PG row
                if not source_ip and pg_row.get("source_ip"):
                    source_ip = pg_row["source_ip"]
                    detail.setdefault("source_ip", source_ip)
                if not detail.get("honeypot") and pg_row.get("honeypot_type"):
                    detail["honeypot"] = pg_row["honeypot_type"]
                if not detail.get("started_at") and pg_row.get("started_at"):
                    detail["started_at"] = pg_row["started_at"]
    except Exception as exc:
        log.debug("PG forensic_sessions query failed for %s: %s", session_id, exc)

    profile_dict: dict = {}
    if source_ip:
        try:
            p = await build_profile(source_ip)
            profile_dict = p.model_dump(mode="json")
        except Exception as exc:
            log.warning("build_profile failed for %s: %s", source_ip, exc)

    # ── Pre-flight: aggregate individual sessions for unified rows ───────────
    # Must run BEFORE MITRE / Kill Chain sections so pg_row is populated
    is_unified = pg_row.get("honeypot_type") == "unified" or session_id.startswith("unified-")
    if is_unified and source_ip:
        try:
            async with session_scope() as db:
                agg = await db.execute(text("""
                    WITH stats AS (
                        SELECT
                            COALESCE(SUM(login_attempts), 0)        AS total_attempts,
                            COALESCE(SUM(success_count), 0)         AS total_success,
                            MAX(kill_chain_stage)                   AS max_kc_stage,
                            MAX(kill_chain_phase)                   AS max_kc_phase,
                            string_agg(DISTINCT forensic_narrative, ' ') AS combined_narrative,
                            array_agg(DISTINCT honeypot_type)       AS honeypot_types
                        FROM forensic_sessions
                        WHERE source_ip = :ip AND honeypot_type != 'unified'
                    ),
                    mitre_flat AS (
                        SELECT DISTINCT elem AS tech
                        FROM forensic_sessions,
                             jsonb_array_elements_text(
                                 CASE WHEN jsonb_typeof(mitre_techniques) = 'array'
                                      THEN mitre_techniques ELSE '[]'::jsonb END
                             ) AS elem
                        WHERE source_ip = :ip AND honeypot_type != 'unified'
                          AND elem IS NOT NULL AND elem != ''
                    ),
                    yara_flat AS (
                        SELECT DISTINCT elem AS rule
                        FROM forensic_sessions,
                             jsonb_array_elements_text(
                                 CASE WHEN jsonb_typeof(enrichment_data->'yara_matches') = 'array'
                                      THEN enrichment_data->'yara_matches' ELSE '[]'::jsonb END
                             ) AS elem
                        WHERE source_ip = :ip AND honeypot_type != 'unified'
                          AND elem IS NOT NULL AND elem != ''
                    )
                    SELECT
                        s.*,
                        (SELECT json_agg(tech) FROM mitre_flat) AS all_mitre,
                        (SELECT json_agg(rule) FROM yara_flat)  AS all_yara
                    FROM stats s
                """), {"ip": source_ip})

                agg_row = agg.mappings().fetchone()
                if agg_row:
                    _total_attempts  = int(agg_row["total_attempts"] or 0)
                    _total_success   = int(agg_row["total_success"] or 0)
                    _max_kc_stage    = int(agg_row["max_kc_stage"] or 0)
                    _max_kc_phase    = agg_row["max_kc_phase"] or ""
                    _combined_narr   = agg_row["combined_narrative"] or ""
                    _honeypot_types  = list(agg_row["honeypot_types"] or [])

                    _agg_mitre = agg_row["all_mitre"] or []
                    if isinstance(_agg_mitre, str):
                        try: _agg_mitre = json.loads(_agg_mitre)
                        except Exception: _agg_mitre = []
                    _agg_mitre = list(dict.fromkeys(t for t in _agg_mitre if t))

                    _agg_yara = agg_row["all_yara"] or []
                    if isinstance(_agg_yara, str):
                        try: _agg_yara = json.loads(_agg_yara)
                        except Exception: _agg_yara = []
                    _agg_yara = list(dict.fromkeys(r for r in _agg_yara if r))

                    if _agg_mitre and not pg_row.get("mitre_techniques"):
                        pg_row["mitre_techniques"] = _agg_mitre
                    if _max_kc_stage > int(pg_row.get("kill_chain_stage") or 0):
                        pg_row["kill_chain_stage"] = _max_kc_stage
                    if _max_kc_phase and not pg_row.get("kill_chain_phase"):
                        pg_row["kill_chain_phase"] = _max_kc_phase

                    if _agg_yara and not profile_dict.get("yara_matches"):
                        profile_dict["yara_matches"] = _agg_yara

                    if not profile_dict.get("ioc_hashes"):
                        cap_r = await db.execute(text("""
                            SELECT enrichment_data->>'captured_file' AS sha
                            FROM forensic_sessions
                            WHERE source_ip = :ip AND honeypot_type != 'unified'
                              AND enrichment_data->>'captured_file' IS NOT NULL
                              AND enrichment_data->>'captured_file' != ''
                            LIMIT 1
                        """), {"ip": source_ip})
                        cap_row = cap_r.mappings().fetchone()
                        if cap_row and cap_row["sha"]:
                            profile_dict["ioc_hashes"] = [cap_row["sha"]]

                    if not detail.get("login_attempts") and _total_attempts > 0:
                        detail["login_attempts"] = [{"success": False, "username": "—", "password": "—"}] * min(_total_attempts, 5)
                        if _total_success > 0:
                            detail["login_attempts"].append({"success": True, "username": "root", "password": "toor"})

                    if _total_attempts > 0:
                        hp_names  = ', '.join(h.upper() for h in _honeypot_types if h)
                        succ_txt  = f"{_total_success} login réussi(s)" if _total_success else "aucun login réussi"
                        yara_txt  = f" YARA: {', '.join(_agg_yara[:2])}." if _agg_yara else ""
                        agg_sum   = (
                            f"IP {source_ip} a attaqué {len(_honeypot_types)} honeypot(s) ({hp_names}). "
                            f"{_total_attempts} tentatives, {succ_txt}. "
                            f"Score: {pg_row.get('risk_score',0)}/100 {pg_row.get('risk_level','')}.{yara_txt} "
                        )
                        if _combined_narr:
                            agg_sum += _combined_narr[:600]
                        profile_dict["mistral_analysis"] = agg_sum
        except Exception as exc:
            log.warning("pre-flight aggregation failed for %s: %s", source_ip, exc)

    # Prefer PG risk_score (forensic engine) over profiler estimate
    if pg_row.get("risk_score") is not None:
        risk_score = int(pg_row["risk_score"])
    else:
        risk_score = int(profile_dict.get("risk_score") or 0)
    risk_label, risk_color = _risk_label_color(risk_score)

    now = datetime.now(tz=timezone.utc)
    report_ref = f"FH-{now.strftime('%Y-%m-%d')}-{session_id[:8]}"
    generated_at_str = f"{now.day} {_MONTHS_EN[now.month]} {now.year} · {now.strftime('%H:%M')} UTC"

    # ── Timeline ──────────────────────────────────────────
    timeline = []
    started = detail.get("started_at")
    if started:
        timeline.append({"ts": str(started), "source": "SESSION", "action": "Session ouverte",
                         "detail": f"Honeypot {(detail.get('honeypot') or 'unknown').upper()}", "mitre": "T1046"})

    logins = detail.get("login_attempts") or []
    for a in logins[:25]:
        ok = a.get("success", False)
        timeline.append({
            "ts": str(a.get("timestamp") or started or ""),
            "source": "AUTH",
            "action": "Tentative auth " + ("✓ SUCCÈS" if ok else "✗ échec"),
            "detail": f"{a.get('username','?')} / {a.get('password','?')}",
            "mitre": "T1078" if ok else "T1110.001",
        })

    cmds = detail.get("commands") or []
    for c in cmds[:25]:
        inp = c.get("input") or c.get("command") or ""
        mitre = "T1059.004"
        if any(x in inp for x in ["wget", "curl", "tftp", "ftp"]):
            mitre = "T1105"
        elif any(x in inp for x in ["cat /etc", "cat /root", "cat /opt"]):
            mitre = "T1552.001"
        elif inp in ["whoami", "id", "uname"]:
            mitre = "T1033"
        timeline.append({"ts": str(c.get("timestamp") or ""), "source": "COMMAND",
                         "action": "Commande exécutée", "detail": inp, "mitre": mitre})

    ended = detail.get("ended_at")
    if ended:
        timeline.append({"ts": str(ended), "source": "SESSION", "action": "Session fermée",
                         "detail": f"Durée : {detail.get('duration_seconds', 0):.1f}s", "mitre": ""})

    try:
        timeline.sort(key=lambda x: x.get("ts") or "")
    except Exception:
        pass

    # ── MITRE rows ────────────────────────────────────────
    auth_success = any(a.get("success") for a in logins)
    mitre_seen: set = set()
    mitre_rows = []

    # PG mitre_techniques take priority over profiler-derived ones
    pg_mitre = pg_row.get("mitre_techniques") or []
    mitre_source = pg_mitre if pg_mitre else (profile_dict.get("mitre_techniques") or [])

    for t_id in mitre_source:
        if t_id in mitre_seen:
            continue
        mitre_seen.add(t_id)
        name, tactic = _mitre_lookup(t_id)
        evidence = "Logs honeypot"
        if "T1110" in t_id:
            attempt_count = pg_row.get("login_attempts") or len(logins)
            if attempt_count:
                evidence = f"{attempt_count} tentatives SSH loggées"
            else:
                evidence = "Credential probing détecté (honeypot logs)"
        elif t_id == "T1078":
            evidence = "Login réussi confirmé"
        elif "T1059" in t_id:
            evidence = f"{len(cmds)} commandes — " + ", ".join((c.get("input") or "")[:20] for c in cmds[:2])
        elif "T1552" in t_id:
            evidence = "Credentials lus"
        elif t_id == "T1105":
            evidence = "wget/curl capturé par Dionaea"
        mitre_rows.append({"id": t_id, "technique": name, "tactic": tactic, "confidence": "100%", "evidence": evidence})

    # Add from commands if not already present
    for c in cmds:
        inp = c.get("input") or ""
        if any(x in inp for x in ["wget", "curl", "tftp"]) and "T1105" not in mitre_seen:
            mitre_seen.add("T1105")
            mitre_rows.append({"id": "T1105", "technique": "Ingress Tool Transfer", "tactic": "Command & Control", "confidence": "100%", "evidence": f"wget {inp[:40]}"})
        if any(x in inp for x in ["whoami", "uname", "id"]) and "T1033" not in mitre_seen:
            mitre_seen.add("T1033")
            mitre_rows.append({"id": "T1033", "technique": "System Owner/User Discovery", "tactic": "Discovery", "confidence": "100%", "evidence": inp})

    if logins and "T1110.001" not in mitre_seen and "T1110" not in mitre_seen:
        mitre_seen.add("T1110.001")
        mitre_rows.insert(0, {"id": "T1110.001", "technique": "Brute Force: Password Guessing", "tactic": "Credential Access", "confidence": "100%", "evidence": f"{len(logins)} tentatives SSH loggées" if len(logins) else "Credential probing détecté (honeypot logs)"})
    if auth_success and "T1078" not in mitre_seen:
        mitre_seen.add("T1078")
        mitre_rows.insert(1, {"id": "T1078", "technique": "Valid Accounts", "tactic": "Initial Access", "confidence": "100%", "evidence": "Login confirmé"})
    if cmds and "T1059.004" not in mitre_seen:
        mitre_seen.add("T1059.004")
        mitre_rows.append({"id": "T1059.004", "technique": "Unix Shell", "tactic": "Execution", "confidence": "100%", "evidence": f"{len(cmds)} commandes exécutées"})

    # ── Kill chain stage ──────────────────────────────────
    # Prefer PG kill_chain_stage (forensic engine) over heuristic
    if pg_row.get("kill_chain_stage") is not None:
        kc_reached = int(pg_row["kill_chain_stage"])
    else:
        kc_reached = 0
        if logins:
            kc_reached = max(kc_reached, 3)  # exploitation
        if auth_success:
            kc_reached = max(kc_reached, 3)
        if cmds:
            kc_reached = max(kc_reached, 4)  # installation
        for c in cmds:
            if any(x in (c.get("input") or "") for x in ["wget", "curl", "tftp"]):
                kc_reached = max(kc_reached, 5)  # C2

    # Inject PG forensic narrative into profile so the template picks it up
    if pg_row.get("forensic_narrative") and not profile_dict.get("mistral_analysis"):
        profile_dict["mistral_analysis"] = pg_row["forensic_narrative"]

    # ── Score signals ──────────────────────────────────────
    # For unified sessions, ip_risk_scores is always authoritative (forensic_sessions
    # may hold a stale breakdown from a prior engine run before re-enrichment).
    # For per-session reports, fall back to forensic_sessions.signal_breakdown.
    sb = {}
    if source_ip:
        try:
            async with session_scope() as db:
                irs = await db.execute(
                    text("SELECT signal_breakdown FROM ip_risk_scores WHERE source_ip = CAST(:ip AS INET) LIMIT 1"),
                    {"ip": source_ip},
                )
                irs_row = irs.mappings().fetchone()
                if irs_row and irs_row["signal_breakdown"]:
                    sb = irs_row["signal_breakdown"]
        except Exception:
            pass
    if not sb:
        sb = pg_row.get("signal_breakdown") or {}
    if sb:
        score_signals = _build_score_signals_from_breakdown(sb)
    else:
        score_signals = _build_score_signals_legacy(profile_dict, detail)

    # ── Malware intelligence — also check PG enrichment_data for captured files ──
    if not profile_dict.get("yara_matches") and not profile_dict.get("ioc_hashes") and source_ip:
        try:
            async with session_scope() as db:
                pg_enrich = await db.execute(text("""
                    SELECT
                        enrichment_data->'yara_matches'   AS yara_matches,
                        enrichment_data->>'captured_file' AS captured_file,
                        enrichment_data->'vt_malicious'   AS vt_malicious
                    FROM forensic_sessions
                    WHERE source_ip = :ip
                      AND enrichment_data->'yara_matches' IS NOT NULL
                      AND jsonb_array_length(enrichment_data->'yara_matches') > 0
                    LIMIT 1
                """), {"ip": source_ip})
                pe_row = pg_enrich.mappings().fetchone()
                if pe_row:
                    ym = pe_row["yara_matches"]
                    if isinstance(ym, str):
                        try: ym = json.loads(ym)
                        except Exception: ym = []
                    if ym:
                        profile_dict["yara_matches"] = ym
                    if pe_row["captured_file"]:
                        profile_dict.setdefault("ioc_hashes", [])
                        if pe_row["captured_file"] not in profile_dict["ioc_hashes"]:
                            profile_dict["ioc_hashes"].insert(0, pe_row["captured_file"])
        except Exception:
            pass
    malware_info = _resolve_malware_info(profile_dict.get("yara_matches") or [])

    # ── VirusTotal result from file_analysis table ─────────
    vt_result: Dict[str, Any] = {}
    captured_sha256 = (profile_dict.get("ioc_hashes") or [""])[0] if profile_dict.get("ioc_hashes") else ""
    if captured_sha256:
        try:
            async with session_scope() as db:
                vt_row = await db.execute(
                    text("SELECT virustotal_result FROM file_analysis WHERE sha256 = :sha LIMIT 1"),
                    {"sha": captured_sha256},
                )
                vt_r = vt_row.mappings().fetchone()
                if vt_r and vt_r["virustotal_result"]:
                    vt_result = vt_r["virustotal_result"]
                    if isinstance(vt_result, str):
                        try: vt_result = json.loads(vt_result)
                        except Exception: vt_result = {}
        except Exception:
            pass

    # ── SHA-256 chain of custody ──────────────────────────
    session_bytes = json.dumps(detail, sort_keys=True, default=str).encode()
    sha256_session = hashlib.sha256(session_bytes).hexdigest()

    # ── Organised score (behavioural estimate) ─────────────
    n_cmd = len(cmds)
    org_score_pct = min(90, int(30 + n_cmd * 4 + (20 if auth_success else 0) + (10 if profile_dict.get("is_tor") else 0)))

    # ── Honeypots hit (for unified sessions) ──────────────
    honeypots_hit = pg_row.get("honeypots_hit") or []
    if isinstance(honeypots_hit, str):
        try: honeypots_hit = json.loads(honeypots_hit)
        except Exception: honeypots_hit = []

    # ── Full enrichment cache data for §02 WHOIS/Shodan ───
    enrichment_cache: Dict[str, Any] = {}
    if source_ip:
        try:
            async with session_scope() as db:
                enc_result = await db.execute(
                    text("SELECT data FROM ip_enrichment_cache WHERE ip = :ip LIMIT 1"),
                    {"ip": source_ip},
                )
                enc_row = enc_result.mappings().fetchone()
                if enc_row:
                    d = enc_row["data"]
                    enrichment_cache = d if isinstance(d, dict) else json.loads(d or "{}")
                    # Fix country: AbuseIPDB is more accurate than MaxMind for datacenter/VPS IPs
                    rep = enrichment_cache.get("reputation", {})
                    if rep.get("country_name") and rep.get("country_code"):
                        old_cc = profile_dict.get("country_iso", "")
                        new_cc = rep["country_code"]
                        profile_dict["country"]     = rep["country_name"]
                        profile_dict["country_iso"] = new_cc
                        # Clear city if it was derived from the wrong country
                        if old_cc and old_cc != new_cc:
                            profile_dict["city"] = ""
                    if rep.get("isp") and not profile_dict.get("isp"):
                        profile_dict["isp"] = rep["isp"]
                    if rep.get("domain") and not profile_dict.get("domain"):
                        profile_dict["domain"] = rep["domain"]
                    if rep.get("usage_type") and not profile_dict.get("usage_type"):
                        profile_dict["usage_type"] = rep["usage_type"]
        except Exception:
            pass

    # ── Ollama recommendations ─────────────────────────────────────────────────
    ollama_recs: List[Dict[str, Any]] = []
    if source_ip:
        try:
            ollama_recs = await get_ollama().generate_recommendations(
                ip=source_ip,
                country=profile_dict.get("country", "unknown"),
                risk_score=risk_score,
                risk_level=risk_label,
                honeypots=honeypots_hit or ([detail.get("honeypot")] if detail.get("honeypot") else []),
                mitre=[r["id"] for r in mitre_rows],
                auth_attempts=int(pg_row.get("login_attempts") or len(logins)),
                auth_success=auth_success,
                yara=profile_dict.get("yara_matches") or [],
                is_tor=bool(profile_dict.get("is_tor")),
                is_vpn=bool(profile_dict.get("is_vpn")),
                commands=[c.get("input", "") for c in cmds[:5]],
            )
        except Exception as exc:
            log.warning("Ollama recommendations failed for %s: %s", source_ip, exc)

    return {
        "session_id": session_id,
        "session": detail,
        "profile": profile_dict,
        "report_ref": report_ref,
        "generated_at_str": generated_at_str,
        "now_year": now.year,
        "risk_label": risk_label,
        "risk_color": risk_color,
        "risk_score": risk_score,
        "timeline": timeline,
        "mitre_rows": mitre_rows,
        "score_signals": score_signals,
        "sha256_session": sha256_session,
        "custody_ok": False,
        "kc_reached": kc_reached,
        "kc_stages": _KC_STAGES,
        "kc_stages_labels": _KC_LABELS,
        "org_score_pct": org_score_pct,
        "auth_success": auth_success,
        "malware_info": malware_info,
        "honeypots_hit": honeypots_hit,
        "enrichment_cache": enrichment_cache,
        "is_unified": is_unified,
        "vt_result": vt_result,
        "vt_malicious": int(profile_dict.get("vt_malicious") or 0),
        "vt_available": bool(profile_dict.get("vt_available", True)),
        "vt_family": profile_dict.get("vt_family") or "",
        "ollama_recommendations": ollama_recs,
        # Jinja2 helper
        "enumerate": enumerate,
    }

router = APIRouter(prefix="/api/reports", tags=["reports"])
limiter = Limiter(key_func=get_remote_address)
_SENSITIVE = get_settings().ratelimit_sensitive


@router.post("/generate", response_model=ReportMeta)
@limiter.limit(_SENSITIVE)
async def generate_report(request: Request, req: ReportRequest = Body(...)) -> ReportMeta:
    if req.scope.value == "ip" and not req.ip:
        raise HTTPException(status_code=400, detail="ip required for ip scope")
    if req.scope.value == "session" and not req.session_id:
        raise HTTPException(status_code=400, detail="session_id required for session scope")
    try:
        return await get_reports().generate(req)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"report generation failed: {exc}")


@router.get("", response_model=ReportListResponse)
async def list_reports(limit: int = Query(100, ge=1, le=500)) -> ReportListResponse:
    total, items = await get_reports().list_reports(limit=limit)
    return ReportListResponse(total=total, items=items)


@router.get("/{report_id}/download")
async def download_report(report_id: str):
    svc = get_reports()
    meta = await svc.get_meta(report_id)
    if not meta:
        raise HTTPException(status_code=404, detail="report not found")
    try:
        path = svc.resolve_pdf_path(meta)
    except FileNotFoundError:
        raise HTTPException(status_code=410, detail="report file missing on disk")
    except PermissionError:
        raise HTTPException(status_code=403, detail="report path rejected")
    return FileResponse(
        path=str(path),
        media_type="application/pdf",
        filename=f"{meta.id}.pdf",
        headers={"X-ForenHive-SHA256": meta.sha256},
    )


@router.post("/{report_id}/stix")
async def export_stix(report_id: str):
    bundle = await get_reports().stix_for(report_id)
    if bundle is None:
        raise HTTPException(status_code=404, detail="report not found")
    return JSONResponse(
        bundle,
        headers={"Content-Disposition": f'attachment; filename="{report_id}.stix.json"'},
    )


# ─── Forensic per-session reports (Sprint 4 surface used by the SPA) ────────


def _phase_from_techniques(mitre: List[str]) -> str | None:
    """Coarse kill-chain phase from MITRE technique prefixes."""
    if not mitre:
        return None
    pfx = {t[:5] for t in mitre if isinstance(t, str)}
    if pfx & {"T1595", "T1590", "T1589"}: return "reconnaissance"
    if pfx & {"T1587", "T1588"}:          return "weaponization"
    if pfx & {"T1566"}:                   return "delivery"
    if pfx & {"T1190", "T1110", "T1203"}: return "exploitation"
    if pfx & {"T1547", "T1543"}:          return "installation"
    if pfx & {"T1071", "T1095"}:          return "command_and_control"
    if pfx & {"T1021", "T1550"}:          return "lateral_movement"
    return "actions_on_objectives"


@router.get("/forensic/sessions")
async def forensic_sessions(limit: int = Query(50, ge=1, le=200)) -> List[Dict[str, Any]]:
    """List sessions in the flat shape the dashboard reconstruction/reporting
    pages expect: session_id, source_ip, honeypot_type, risk_score,
    kill_chain_phase, primary_technique, started_at.

    Queries PostgreSQL forensic_sessions (written by the forensic engine) first,
    falls back to raw ES sessions if PostgreSQL is empty or unavailable.
    """
    from sqlalchemy import text
    from db import session_scope

    pg_rows: List[Dict[str, Any]] = []
    try:
        async with session_scope() as db:
            result = await db.execute(
                text(
                    """
                    SELECT session_id, source_ip, honeypot_type,
                           risk_score, kill_chain_phase, kill_chain_stage,
                           primary_technique, forensic_narrative,
                           mitre_techniques, started_at
                    FROM forensic_sessions
                    ORDER BY started_at DESC
                    LIMIT :lim
                    """
                ),
                {"lim": limit},
            )
            for row in result.mappings():
                mitre = row["mitre_techniques"] or []
                if isinstance(mitre, str):
                    try:
                        mitre = json.loads(mitre)
                    except Exception:
                        mitre = []
                pg_rows.append({
                    "session_id":        row["session_id"],
                    "source_ip":         row["source_ip"],
                    "honeypot_type":     row["honeypot_type"],
                    "risk_score":        row["risk_score"],
                    "kill_chain_phase":  row["kill_chain_phase"],
                    "kill_chain_stage":  row["kill_chain_stage"],
                    "primary_technique": row["primary_technique"],
                    "started_at":        row["started_at"],
                })
    except Exception as exc:
        log.warning("forensic_sessions: PG query failed (%s), falling back to ES", exc)

    if pg_rows:
        return pg_rows

    # Fallback: raw ES sessions (no forensic engine data yet)
    rows = await get_es().sessions(limit=limit, active_only=False)
    out: List[Dict[str, Any]] = []
    for r in rows:
        mitre = r.get("mitre_techniques") or r.get("techniques") or []
        if isinstance(mitre, dict):
            mitre = []
        out.append({
            "session_id":        r.get("session_id"),
            "source_ip":         r.get("source_ip"),
            "honeypot_type":     r.get("honeypot") or r.get("honeypot_type"),
            "risk_score":        r.get("risk_score"),
            "kill_chain_phase":  r.get("kill_chain_phase") or _phase_from_techniques(mitre),
            "kill_chain_stage":  r.get("kill_chain_stage"),
            "primary_technique": (mitre[0] if mitre else r.get("primary_technique")),
            "started_at":        r.get("started_at"),
        })
    return out


@router.post("/forensic/{session_id}/generate")
async def forensic_generate(request: Request, session_id: str):
    """Generate and download a forensic PDF for one session using the rich forensic template."""
    try:
        from weasyprint import HTML as WeasyprintHTML
    except ImportError:
        raise HTTPException(status_code=503, detail="WeasyPrint not installed")

    try:
        ctx = await _build_forensic_context(session_id)
    except Exception as exc:
        log.exception("forensic context build failed for %s", session_id)
        raise HTTPException(status_code=500, detail=f"context build failed: {exc}")

    # Session not found in ES or PG
    if not ctx["session"].get("source_ip") and not ctx["profile"].get("ip"):
        raise HTTPException(status_code=404, detail="session not found")

    v2_ctx = _adapt_context_for_v2(ctx)

    env = Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=select_autoescape(["html"]),
    )
    env.globals["enumerate"] = enumerate
    try:
        html_body = env.get_template("forenhive_rapport_v2.html").render(**v2_ctx)
    except Exception as exc:
        log.exception("template render failed")
        raise HTTPException(status_code=500, detail=f"template render failed: {exc}")

    settings = get_settings()
    out_dir = Path(settings.reports_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    pdf_path = out_dir / f"forensic-{session_id}-{uuid.uuid4().hex[:8]}.pdf"

    try:
        WeasyprintHTML(string=html_body).write_pdf(str(pdf_path))
    except Exception as exc:
        log.exception("WeasyPrint render failed")
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {exc}")

    pdf_bytes = pdf_path.read_bytes()
    sha256 = hashlib.sha256(pdf_bytes).hexdigest()

    return FileResponse(
        path=str(pdf_path),
        media_type="application/pdf",
        filename=f"ForenHive-{v2_ctx['report_id']}.pdf",
        headers={
            "X-PDF-SHA256": sha256,
            "X-ForenHive-SHA256": sha256,
            "Content-Disposition": f'attachment; filename="ForenHive-{v2_ctx["report_id"]}.pdf"',
        },
    )


@router.get("/forensic/{session_id}/preview")
async def forensic_preview(session_id: str):
    """Full forensic HTML dossier for a single session (rich preview matching the PDF design)."""
    try:
        ctx = await _build_forensic_context(session_id)
    except Exception as exc:
        log.exception("forensic context build failed for %s", session_id)
        raise HTTPException(status_code=500, detail=f"context build failed: {exc}")

    # Session not found in ES or PG
    if not ctx["session"].get("source_ip") and not ctx["profile"].get("ip"):
        raise HTTPException(status_code=404, detail="session not found")

    v2_ctx = _adapt_context_for_v2(ctx)

    env = Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=select_autoescape(["html"]),
    )
    env.globals["enumerate"] = enumerate
    try:
        html_body = env.get_template("forenhive_rapport_v2.html").render(**v2_ctx)
    except Exception as exc:
        log.exception("template render failed")
        raise HTTPException(status_code=500, detail=f"template render failed: {exc}")
    return HTMLResponse(html_body)
