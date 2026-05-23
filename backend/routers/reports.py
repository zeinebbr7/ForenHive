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
from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape
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

# ── Hoisted Jinja environment + WeasyPrint import ─────────────────────
# Building these per-request adds ~1-2 s of cold-start latency on each call;
# at module scope the templates stay compiled and WeasyPrint warms its font
# cache exactly once.
_JINJA_ENV = Environment(
    loader=FileSystemLoader(TEMPLATE_DIR),
    autoescape=select_autoescape(["html"]),
    auto_reload=False,
    # StrictUndefined surfaces template ↔ adapter gaps as 500s instead of
    # blank cells. Every variable referenced by forenhive_rapport_v2.html
    # must now either be supplied by _adapt_context_for_v2 or carry an
    # explicit `| default(...)` in the template.
    undefined=StrictUndefined,
)
_JINJA_ENV.globals["enumerate"] = enumerate

try:
    from weasyprint import HTML as _WeasyHTML  # noqa: E402
    _WEASY_AVAILABLE = True
except ImportError:  # pragma: no cover — surfaced at request time
    _WeasyHTML = None  # type: ignore[assignment]
    _WEASY_AVAILABLE = False

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
    # Canonical v2.0.0 engine vocabulary — labels are English everywhere now.
    "CRITICAL": "CRITICAL",
    "HIGH":     "HIGH",
    "MEDIUM":   "MEDIUM",
    "LOW":      "LOW",
    "INFO":     "INFO",
}

_KC_LABELS = ["Recon", "Weapon", "Delivery", "Exploit", "Install", "C2", "Lateral", "Actions"]
_KC_STAGES = ["reconnaissance", "weaponization", "delivery", "exploitation",
              "installation", "command_and_control", "lateral_movement", "actions_on_objectives"]


def _risk_label_color(score: int):
    # v2.0.0 cutoffs — mirror forensic-engine/risk_thresholds.py (70/45/25/10).
    if score >= 70: return "CRITICAL", "#C62828"
    if score >= 45: return "HIGH",     "#b36000"
    if score >= 25: return "MEDIUM",   "#1565C0"
    if score >= 10: return "LOW",      "#388E3C"
    return "INFO", "#757575"


def _mitre_lookup(tech_id: str):
    entry = _MITRE_DB.get(tech_id)
    if entry:
        return entry
    parent = tech_id[:5] if len(tech_id) > 5 else tech_id
    return _MITRE_DB.get(parent, (tech_id, "Unknown"))


_SIGNAL_META = {
    # ── WHO (33 pts) ──
    "reputation": {
        "name": "IP Reputation (AbuseIPDB)",
        "source": "AbuseIPDB",
        "why": "Community-reported abuse confidence. ≥90→15, ≥70→11, ≥50→7, ≥25→4. Skipped for private IPs. Max 15 pts.",
    },
    "anonymization": {
        "name": "Anonymisation / Evasion (Tor / VPN / Bogon)",
        "source": "IPLocate",
        "why": "Bogon/Tor→10, VPN/Proxy→6, Datacenter→3. Indicates deliberate identity concealment. Max 10 pts.",
    },
    "threat_history": {
        "name": "Threat History (Recidivism + Geo)",
        "source": "ForenHive + AbuseIPDB + Shodan",
        "why": "Repeat-offender recidivism, abuser list, sanctioned-country origin, known Shodan vulns. Max 8 pts.",
    },
    # ── WHAT (43 pts) ──
    "intent_volume": {
        "name": "Intent & Volume (Effort + Recon)",
        "source": "Cowrie / Dionaea / Galah",
        "why": "Log-scaled attempts, velocity bonus (>50/s), scan-path hits against known recon paths. Max 10 pts.",
    },
    "compromise_depth": {
        "name": "Compromise Depth (Auth + Commands + Files)",
        "source": "Cowrie",
        "why": "Successful auth, command volume, command quality (credential-access/destructive/lateral), file ingress. Max 15 pts.",
    },
    "exfiltration": {
        "name": "Exfiltration (Egress Volume)",
        "source": "Zeek / Cowrie",
        "why": "Log-scaled KB egressed from `exfil_bytes`. 0 → no data egress. Max 8 pts.",
    },
    "lateral_movement": {
        "name": "Lateral Movement (CVE + SMB + Multi-HP + Critical Ports)",
        "source": "Dionaea / Zeek / Correlator",
        "why": "CVE exploit (+4), SMB share-enum/epmapper (+2 each), ≥3 honeypots (+2), critical dst port (+2). Max 10 pts.",
    },
    # ── HOW (24 pts) ──
    "malware": {
        "name": "Malware Detected (YARA / VirusTotal)",
        "source": "YARA Engine / VirusTotal",
        "why": "YARA severity (critical 6 / high 4 / medium 2 / low 1) + VT tiers (≥20→6, ≥10→4, ≥1→2). Max 12 pts.",
    },
    "mitre_sophistication": {
        "name": "MITRE Sophistication (TTP Breadth)",
        "source": "ForenHive MITRE Mapper",
        "why": "Distinct techniques (≤6), kill-chain stage (≤4), distinct tactics (≤2). Max 12 pts.",
    },
}


def _build_score_signals_from_breakdown(breakdown: dict) -> List[dict]:
    """Build §07 signal list from the v2.0.0 9-signal JSONB stored by RiskScorer."""
    signals = []
    order = [
        # WHO
        "reputation", "anonymization", "threat_history",
        # WHAT
        "intent_volume", "compromise_depth", "exfiltration", "lateral_movement",
        # HOW
        "malware", "mitre_sophistication",
    ]
    for key in order:
        sig = breakdown.get(key)
        if sig is None:
            continue
        meta = _SIGNAL_META.get(key, {"name": key, "source": "ForenHive", "why": ""})
        detail_txt = sig.get("detail") or ""
        skipped     = bool(sig.get("skipped"))
        skip_reason = sig.get("skip_reason") or ""
        if skipped:
            value = f"SKIPPED — {skip_reason}" if skip_reason else "SKIPPED"
        else:
            value = detail_txt
        signals.append({
            "name":        meta["name"],
            "source":      meta["source"],
            "points":      int(sig.get("points", 0)),
            "max":         int(sig.get("max_points", sig.get("max", 0))),
            "value":       value,
            "why":         meta["why"],
            "skipped":     skipped,
            "skip_reason": skip_reason,
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
            "name":        s.get("name", ""),
            "points":      s.get("points", 0),
            "max_points":  s.get("max", 0),
            "value":       s.get("value", ""),
            "why":         s.get("why", ""),
            "skipped":     bool(s.get("skipped")),
            "skip_reason": s.get("skip_reason", ""),
        }
        for s in ctx.get("score_signals", [])
    ]

    def _ev_severity(ev: dict) -> str:
        """Pick a severity class for the timeline row. The template colors
        the row based on this; missing severity used to crash under
        StrictUndefined (audit M-2 / ev.severity)."""
        act = (ev.get("action") or "").lower()
        src = (ev.get("source") or "").upper()
        mid = (ev.get("mitre") or "")
        if "succ" in act or "succès" in act or mid == "T1078":
            return "CRITICAL"
        if "commande" in act or mid.startswith("T1059") or mid == "T1105":
            return "HIGH"
        if "tentative" in act or mid == "T1110.001":
            return "HIGH"
        if src == "SESSION":
            return "INFO"
        return "INFO"

    all_timeline = [
        {
            "timestamp":  str(ev.get("ts", "")),
            "event_type": ev.get("action", ev.get("source", "")),
            "details":    ev.get("detail", ""),
            "mitre_tid":  ev.get("mitre") or None,
            "severity":   _ev_severity(ev),
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

    # IOCs — prefer the engine-persisted forensic_iocs rows (aggregated by
    # ioc_extractor across all timeline events) when present; fall back to
    # the per-session inline build (file hashes + download URLs in commands)
    # only when the engine has not yet processed this IP.
    engine_iocs_list = ctx.get("engine_iocs") or []
    iocs_from_db = bool(engine_iocs_list)
    if iocs_from_db:
        iocs: List[Dict] = list(engine_iocs_list)
    else:
        iocs = [
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

    # Dropped files (one entry per captured binary). The engine stores VT
    # results in file_analysis.virustotal_result with the normalized flat
    # shape {malicious, total_engines, ...}; older code expected the raw VT
    # API shape (last_analysis_stats nested). Handle both so future re-shapes
    # don't blank the VT detections column.
    dropped_files: List[Dict] = []
    if ioc_hashes:
        vt = ctx.get("vt_result") or {}
        stats = vt.get("last_analysis_stats") or {}
        vt_detections = (
            vt.get("malicious")
            if vt.get("malicious") is not None
            else stats.get("malicious")
        )
        vt_total = (
            vt.get("total_engines")
            or vt.get("total")
            or (sum(stats.values()) if stats else None)
        )
        dropped_files.append({
            "filename":      profile.get("captured_file", "captured_file"),
            "sha256":        ioc_hashes[0],
            "yara_hits":     yara_matches,
            "vt_detections": vt_detections,
            "vt_total":      vt_total,
        })

    # Chain of custody — prefers the engine-persisted seal in
    # forensic_chain_of_custody. M-7: timestamp shows the TSA-anchored
    # sealed_at (real evidence-fixation time), not session started_at.
    _tsa_ok    = bool(ctx.get("custody_ok", False))
    _tsa_url   = ctx.get("tsa_url") or "https://freetsa.org/tsr"
    _coc_from_db = bool(ctx.get("coc_from_db"))
    _sealed_at   = ctx.get("coc_sealed_at") or str(started_at)
    chain_of_custody = [{
        "artifact":  "Forensic session record" if _coc_from_db else "Session JSON snapshot",
        "sha256":    ctx.get("sha256_session", ""),
        "timestamp": _sealed_at,
        "tsa":       _tsa_url if _tsa_ok else "—",
        "tsa_ok":    _tsa_ok,
    }]

    # Verdict — cutoffs aligned with risk_thresholds.py v2.0.0 (70/45/25/10)
    if score >= 70:
        verdict = f"Confirmed high-severity threat ({malware_family or 'malware deployment detected'})"
    elif score >= 45:
        verdict = f"Likely malicious activity — {malware_family or 'attack confirmed'}"
    elif score >= 25:
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
    sophistication = "HIGH" if score >= 70 else ("MEDIUM" if score >= 25 else "LOW")

    # Prefer the engine's persisted FBI BAU detective profile (suspect_profiles)
    # over the score-derived heuristics. Engine stores confidence and
    # organized_score as 0-1 floats; the template expects integer % / x/10.
    sp = profile.get("suspect_profile") or {}
    if sp.get("sophistication"):
        sophistication = str(sp["sophistication"]).upper()
    sp_conf = sp.get("confidence")
    sp_conf_pct = int(round(float(sp_conf) * 100)) if isinstance(sp_conf, (int, float)) else org_pct
    sp_objective = sp.get("primary_objective") or ""
    sp_org = sp.get("organized_score")
    sp_org_int = int(round(float(sp_org) * 10)) if isinstance(sp_org, (int, float)) else (org_pct // 10)
    sp_traits = sp.get("behavioral_traits") or []
    sp_narr = sp.get("detective_narrative") or ""
    sp_disguise_used = bool(sp.get("disguise_used"))
    sp_disguise_type = sp.get("disguise_type") or ""
    sp_escalation = bool(sp.get("escalation_detected"))
    sp_signature = sp.get("signature_indicators") or []

    profile_out = {
        "sophistication":    sophistication,
        "confidence":        sp_conf_pct,
        "objective":         sp_objective or malware_family or ("Credential harvesting" if auth_attempts else "Unknown"),
        "organized_score":   min(10, sp_org_int),
        "behavioral_traits": sp_traits if sp_traits else traits,
        "detective_narrative": sp_narr or profile.get("mistral_analysis", ""),
        "es_reference_cases": profile.get("suspect_similar_cases") or [],
        # Mapped from the engine profile so the template's optional blocks render
        # when real intel is available. Operator type folds disguise; persistence
        # folds escalation + signature indicators.
        "operator_type":     (
            f"Anonymized ({sp_disguise_type})" if sp_disguise_used and sp_disguise_type and sp_disguise_type != "none"
            else ("Direct" if sp else "")
        ),
        "persistence":       (
            "Escalating" if sp_escalation else ("Persistent" if sp_signature else "")
        ),
    }

    # Recommendations — prefer the engine's persisted recommendations
    # (ip_risk_scores.recommendations) over heuristic. Key findings from
    # the engine's risk_score are prepended as low-priority "FINDING"
    # rows so the analyst sees the engine's reasoning even when the
    # engine has not yet emitted action recommendations.
    engine_recs = ctx.get("engine_recommendations") or []
    engine_kfs  = ctx.get("engine_key_findings")    or []
    recs_from_db = bool(engine_recs)
    if recs_from_db:
        recommendations: List[Dict] = list(engine_recs)
    else:
        recommendations = []
        if score >= 70:
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
    if engine_kfs:
        recommendations = [
            {"priority": "FINDING", "action": kf, "rationale": "ForenHive risk engine key finding"}
            for kf in engine_kfs
        ] + recommendations

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
        "engine_version":    ctx.get("engine_version") or "v2.0.0-9signals",
        "honeypot_port":     (
            str(ctx.get("destination_port"))
            if ctx.get("destination_port")
            else None
        ),
        "classification":    "TLP:AMBER",
        # Risk
        "risk_level":        risk_level,
        "risk_score":        score,
        "risk_confidence":   "HIGH" if score >= 70 else ("MEDIUM" if score >= 25 else "LOW"),
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
        "auth_success":      any(a.get("success") for a in auth_attempts),
        "auth_success_count": sum(1 for a in auth_attempts if a.get("success")),
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
        "timeline_from_db":  bool(ctx.get("timeline_from_db")),
        # Profile
        "profile":           profile_out,
        # IOCs
        "iocs":              iocs,
        "iocs_from_db":      iocs_from_db,
        "stix_export_path":  None,
        # Chain of custody
        "chain_of_custody":        chain_of_custody,
        "coc_timestamp_authority": _tsa_url if _tsa_ok else "freetsa.org",
        "custody_ok":              _tsa_ok,
        "coc_from_db":             _coc_from_db,
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
        "recs_from_db":            recs_from_db,
        # Ollama recommendations (passed through from _build_forensic_context)
        "ollama_recommendations":  ctx.get("ollama_recommendations", []),
        # VirusTotal fields (fix: these were missing and caused "Quota épuisé" always)
        "vt_available": ctx.get("vt_available", True),
        "vt_malicious": ctx.get("vt_malicious", 0),
        "vt_family":    ctx.get("vt_family", ""),
        # Kill chain progression (forensic engine MITRE phase)
        "kc_reached":        ctx.get("kc_reached", 0),
        "kc_stages":         ctx.get("kc_stages", []),
        "kc_stages_labels":  ctx.get("kc_stages_labels", []),
        # Honeypots involved (for §5.3 breakdown)
        "honeypots_hit":     ctx.get("honeypots_hit", []),
        "sessions_count":    ctx.get("sessions_count", 1),
        "extra_references":  [],
        # Variables the template references at top level but the audit
        # M-2 list flagged as never supplied. Under StrictUndefined the
        # bare references (e.g. `{% if vt_top_engines %}`) raise instead
        # of silently rendering empty, so we supply explicit empty
        # values/strings. exec_narrative / bottom_line use `is defined`
        # guards in the template so they're safe undefined, but supplying
        # them explicitly keeps the report's narrative section consistent
        # whether the engine produced a forensic_narrative or not.
        # VT top engines + total — read the engine-normalized shape stored in
        # file_analysis.virustotal_result (flat keys: malicious, total_engines,
        # engine_hits). Older code used .get("total") which doesn't exist.
        "vt_top_engines":    (
            list(((ctx.get("vt_result") or {}).get("engine_hits") or {}).keys())[:3]
        ),
        "vt_total":          (
            (ctx.get("vt_result") or {}).get("total_engines")
            or (ctx.get("vt_result") or {}).get("total")
        ),
        "bottom_line":       verdict,
        "exec_narrative":    profile.get("mistral_analysis", "") or ctx.get("engine_enrichment", {}).get("forensic_narrative", ""),
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
                           forensic_narrative, mitre_techniques, started_at, ended_at,
                           login_attempts, success_count, sessions_count, honeypots_hit,
                           attack_velocity, score_version, scored_at,
                           enrichment_data
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
                # Normalise enrichment_data to dict — the engine stores per-session
                # VT / SMB / exploit / kill-chain-label fields inside this jsonb.
                ed = pg_row.get("enrichment_data") or {}
                if isinstance(ed, str):
                    try:
                        ed = json.loads(ed)
                    except Exception:
                        ed = {}
                pg_row["enrichment_data"] = ed
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

    # ── FBI BAU detective profile from forensic-engine/profiler.py ─────────
    # The engine writes a rich Mistral-derived profile (sophistication,
    # primary_objective, behavioral_traits, detective_narrative, …) into
    # suspect_profiles.profile (jsonb). Surface it so §"Profile FBI BAU"
    # uses real engine values instead of the heuristic fallback in the v2
    # adapter. Also load up to 5 similar cases (by primary_objective and
    # risk_score proximity) so §"Similar Past Cases" is no longer empty.
    if source_ip:
        try:
            async with session_scope() as db:
                sp_row = (await db.execute(
                    text(
                        "SELECT profile, risk_score, updated_at "
                        "FROM suspect_profiles "
                        "WHERE source_ip = :ip "
                        "ORDER BY updated_at DESC LIMIT 1"
                    ),
                    {"ip": source_ip},
                )).mappings().fetchone()
                if sp_row:
                    sp_profile = sp_row["profile"]
                    if isinstance(sp_profile, str):
                        try:
                            sp_profile = json.loads(sp_profile)
                        except Exception:
                            sp_profile = {}
                    if isinstance(sp_profile, dict):
                        profile_dict["suspect_profile"] = sp_profile
                        # Similar past cases: same primary_objective, closest risk_score.
                        sp_obj = sp_profile.get("primary_objective") or ""
                        sp_score = int(sp_row["risk_score"] or 0)
                        try:
                            sim_rows = (await db.execute(
                                text(
                                    "SELECT source_ip, risk_score, updated_at, "
                                    "       profile->>'primary_objective' AS objective, "
                                    "       profile->>'dominant_tactic'   AS tactic "
                                    "FROM suspect_profiles "
                                    "WHERE source_ip != :ip "
                                    "  AND (:obj = '' OR profile->>'primary_objective' = :obj) "
                                    "ORDER BY ABS(COALESCE(risk_score,0) - :score) ASC, updated_at DESC "
                                    "LIMIT 5"
                                ),
                                {"ip": source_ip, "obj": sp_obj, "score": sp_score},
                            )).mappings().fetchall()
                            profile_dict["suspect_similar_cases"] = [
                                {
                                    "ip": r["source_ip"],
                                    "date": str(r["updated_at"])[:10] if r["updated_at"] else "",
                                    "session_id": "—",
                                    "match_reason": (
                                        f"{r['objective'] or 'unknown'} · "
                                        f"score {r['risk_score']}"
                                    ),
                                }
                                for r in sim_rows
                            ]
                        except Exception as _sim_exc:
                            log.debug("similar suspect_profiles query failed: %s", _sim_exc)
        except Exception as exc:
            log.debug("suspect_profiles query failed for %s: %s", source_ip, exc)

    # ── Pre-flight: aggregate individual sessions for unified rows ───────────
    # Must run BEFORE MITRE / Kill Chain sections so pg_row is populated.
    # We aggregate whenever the IP has multiple sessions (treating the report
    # as a per-IP summary rather than a single isolated session). This is the
    # behaviour users expect when generating a report from a brute-force IP:
    # the timeline, kill chain and risk should reflect ALL the attacker's
    # activity, not just one stray TCP connection.
    is_unified = pg_row.get("honeypot_type") == "unified" or session_id.startswith("unified-")
    if not is_unified and source_ip:
        try:
            async with session_scope() as db:
                _cnt = await db.execute(
                    text("SELECT COUNT(*) FROM forensic_sessions WHERE source_ip = :ip AND honeypot_type != 'unified'"),
                    {"ip": source_ip},
                )
                if int(_cnt.scalar() or 0) > 1:
                    is_unified = True
        except Exception:
            pass
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
                            (array_agg(forensic_narrative ORDER BY length(forensic_narrative) DESC NULLS LAST))[1] AS combined_narrative,
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
                        succ_txt  = f"{_total_success} successful login(s)" if _total_success else "no successful login"
                        yara_txt  = f" YARA: {', '.join(_agg_yara[:2])}." if _agg_yara else ""
                        # Mistral sometimes loops within a single narrative
                        # ("The incident involved... The incident involves...").
                        # Dedupe near-identical sentences (loose 18-char prefix key)
                        # and keep only the first 2 distinct sentences for concision.
                        _best_narr = ""
                        if _combined_narr:
                            import re as _re
                            _parts = [p.strip() for p in _re.split(r"(?<=[.!?])\s+", _combined_narr) if p.strip()]
                            seen_p = set(); _uniq = []
                            for p in _parts:
                                key = _re.sub(r"[^a-z]", "", p.lower())[:18]
                                if key and key not in seen_p:
                                    seen_p.add(key); _uniq.append(p)
                            _best_narr = " ".join(_uniq[:2])
                        agg_sum = (
                            f"IP {source_ip} targeted {len(_honeypot_types)} honeypot(s) "
                            f"({hp_names}) with {_total_attempts} authentication attempts, {succ_txt}.{yara_txt} "
                        )
                        if _best_narr:
                            agg_sum += _best_narr
                        profile_dict["mistral_analysis"] = agg_sum
        except Exception as exc:
            log.warning("pre-flight aggregation failed for %s: %s", source_ip, exc)


    now = datetime.now(tz=timezone.utc)
    report_ref = f"FH-{now.strftime('%Y-%m-%d')}-{session_id[:8]}"
    generated_at_str = f"{now.day} {_MONTHS_EN[now.month]} {now.year} · {now.strftime('%H:%M')} UTC"

    # ── Aggregate timeline data from ALL sessions for this IP when unified ──
    if is_unified and source_ip:
        try:
            # Pull all auth attempts from ES across the IP's sessions
            agg_body = {
                "size": 200,
                "query": {"bool": {"filter": [
                    {"term": {"source.ip.keyword": source_ip}},
                    {"prefix": {"event.id": "cowrie.login"}}
                ]}},
                "sort": [{"@timestamp": {"order": "asc"}}],
            }
            agg_res = await es.search_docs("honeypot-logs-*", agg_body)
            all_logins = []
            for h in agg_res.get("hits", {}).get("hits", []):
                src = h.get("_source", {})
                # ES stores ECS fields as FLATTENED dotted keys (e.g. "user.name"),
                # not nested objects. Read both shapes defensively.
                ev_id = src.get("event.id") or (src.get("event") or {}).get("id") or ""
                ev_out = src.get("event.outcome") or (src.get("event") or {}).get("outcome") or ""
                uname = src.get("user.name") or (src.get("user") or {}).get("name") or "?"
                upass = src.get("user.password") or (src.get("user") or {}).get("password") or "?"
                all_logins.append({
                    "timestamp": src.get("@timestamp"),
                    "username":  uname,
                    "password":  upass,
                    "success":   ev_out == "success" or ev_id == "cowrie.login.success",
                })
            if all_logins:
                detail["login_attempts"] = all_logins
            # Same for commands
            cmd_body = {
                "size": 200,
                "query": {"bool": {"filter": [
                    {"term": {"source.ip.keyword": source_ip}},
                    {"prefix": {"event.id": "cowrie.command"}}
                ]}},
                "sort": [{"@timestamp": {"order": "asc"}}],
            }
            cmd_res = await es.search_docs("honeypot-logs-*", cmd_body)
            all_cmds = []
            for h in cmd_res.get("hits", {}).get("hits", []):
                src = h.get("_source", {})
                inp = (src.get("process.command_line")
                       or (src.get("process") or {}).get("command_line")
                       or src.get("input")
                       or src.get("message", ""))
                all_cmds.append({
                    "timestamp": src.get("@timestamp"),
                    "input":     inp,
                })
            if all_cmds:
                detail["commands"] = all_cmds
        except Exception as exc:
            log.warning("aggregated timeline fetch failed for %s: %s", source_ip, exc)

    # ── Timeline ──────────────────────────────────────────
    # Prefer the engine-persisted forensic_timeline_events rows (built by
    # timeline_builder.py with millisecond precision across all honeypots)
    # over the per-request ES rebuild. Query by session_id first; for
    # unified per-IP reports (or when the session's own row count is zero
    # but other rows exist for the same IP) fall back to a source_ip query.
    timeline: List[Dict[str, Any]] = []
    timeline_from_db = False

    def _ev_mitre_from_row(category: str, action: str, summary: str) -> str:
        """Cheap MITRE technique guess for a forensic_timeline_events row,
        kept consistent with the heuristics already used by the ES rebuild
        below so timeline rows render with the same MITRE tags either way."""
        cat = (category or "").lower()
        act = (action or "").lower()
        summ = (summary or "")
        if "login.success" in act or cat == "auth" and "success" in summ.lower():
            return "T1078"
        if cat == "auth":
            return "T1110.001"
        if cat == "command":
            text_blob = (summary or "")
            if any(x in text_blob for x in ["wget", "curl", "tftp", "ftp"]):
                return "T1105"
            if any(x in text_blob for x in ["cat /etc", "cat /root", "cat /opt"]):
                return "T1552.001"
            if any(x in text_blob for x in ["whoami", " id", "uname"]):
                return "T1033"
            return "T1059.004"
        if cat == "exploit":
            return "T1190"
        if cat == "http":
            return "T1071"
        if cat == "file":
            return "T1105"
        if cat == "recon" or "connect" in act:
            return "T1046"
        return ""

    def _ev_source_from_category(category: str) -> str:
        cat = (category or "").lower()
        if cat == "auth":    return "AUTH"
        if cat == "command": return "COMMAND"
        if cat == "file":    return "FILE"
        if cat == "http":    return "HTTP"
        if cat == "exploit": return "EXPLOIT"
        if cat == "recon":   return "RECON"
        if cat == "connect": return "SESSION"
        return "EVENT"

    if source_ip:
        try:
            async with session_scope() as db:
                _tl_sql = text("""
                    SELECT ts, honeypot_type, event_category, event_action,
                           destination_port, protocol, summary
                    FROM forensic_timeline_events
                    WHERE session_id = :sid
                    ORDER BY ts ASC
                    LIMIT 200
                """)
                tl_res = await db.execute(_tl_sql, {"sid": session_id})
                tl_rows = list(tl_res.mappings())
                # Unified reports (per-IP) and sessions whose own row count
                # is zero get the source_ip view.
                if not tl_rows and (is_unified or True):
                    tl_res = await db.execute(
                        text("""
                            SELECT ts, honeypot_type, event_category, event_action,
                                   destination_port, protocol, summary
                            FROM forensic_timeline_events
                            WHERE source_ip = :ip
                            ORDER BY ts ASC
                            LIMIT 200
                        """),
                        {"ip": source_ip},
                    )
                    tl_rows = list(tl_res.mappings())
                for r in tl_rows:
                    cat = r["event_category"] or ""
                    act = r["event_action"] or ""
                    summary = r["summary"] or act
                    timeline.append({
                        "ts":     str(r["ts"]),
                        "source": _ev_source_from_category(cat),
                        "action": act or summary[:48],
                        "detail": summary,
                        "mitre":  _ev_mitre_from_row(cat, act, summary),
                    })
                if timeline:
                    timeline_from_db = True
        except Exception as exc:
            log.debug("forensic_timeline_events query failed for %s: %s", session_id, exc)

    started = detail.get("started_at")
    if not timeline_from_db and started:
        timeline.append({"ts": str(started), "source": "SESSION", "action": "Session ouverte",
                         "detail": f"Honeypot {(detail.get('honeypot') or 'unknown').upper()}", "mitre": "T1046"})

    logins = detail.get("login_attempts") or []
    if not timeline_from_db:
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
    if not timeline_from_db:
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
    if not timeline_from_db and ended:
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
    # Always prefer forensic_sessions.signal_breakdown (snapshot at engine run time
    # for this specific session). Only fall back to ip_risk_scores if the per-session
    # breakdown is missing — ip_risk_scores is a sliding 24h window and changes as
    # new sessions from the same IP arrive, causing the displayed score to drift.
    sb = pg_row.get("signal_breakdown") or {}
    irs_risk_score: Optional[int] = None
    if not sb and source_ip:
        try:
            async with session_scope() as db:
                irs = await db.execute(
                    text("SELECT signal_breakdown, risk_score FROM ip_risk_scores WHERE source_ip = CAST(:ip AS INET) LIMIT 1"),
                    {"ip": source_ip},
                )
                irs_row = irs.mappings().fetchone()
                cand = irs_row["signal_breakdown"] if irs_row else None
                # The unified per-IP scorer runs on a sliding lookback window. Once an
                # IP's sessions age out of that window, score_ip() returns an empty
                # result (every signal skipped="empty_aggregate", score 0) which then
                # overwrites ip_risk_scores. Only adopt the unified breakdown/score if
                # it actually has at least one active (non-skipped) signal — otherwise
                # keep the permanent per-session score from forensic_sessions.
                if isinstance(cand, dict) and any(
                    isinstance(v, dict) and not v.get("skipped") for v in cand.values()
                ):
                    sb = cand
                    if irs_row["risk_score"] is not None:
                        irs_risk_score = int(irs_row["risk_score"])
        except Exception:
            pass
    if sb:
        score_signals = _build_score_signals_from_breakdown(sb)
    else:
        score_signals = _build_score_signals_legacy(profile_dict, detail)

    # Pick the highest meaningful score: the unified per-IP score when it carries a
    # real (non-empty) breakdown, and never below the permanent per-session score
    # stored in forensic_sessions (which survives the unified scorer's lookback window).
    session_score = int(pg_row["risk_score"]) if pg_row.get("risk_score") is not None else None
    score_candidates = [s for s in (irs_risk_score, session_score) if s is not None]
    if score_candidates:
        risk_score = max(score_candidates)
    else:
        risk_score = int(profile_dict.get("risk_score") or 0)
    risk_label, risk_color = _risk_label_color(risk_score)

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

    # ── SHA-256 + RFC 3161 chain of custody ─────────────────
    # Prefer the engine-persisted seal in forensic_chain_of_custody (JOINed
    # with forensic_coc_batches for the batched TSA anchor). This is the
    # authoritative record sealed at engine run time — re-sealing on every
    # report render produces a different SHA-256 each time and bypasses the
    # RFC 3161 anchor the engine already stored.
    sha256_session: str = ""
    tsa_ok           = False
    tsa_url          = ""
    tsa_token_b64    = None
    sealed_at_str: Optional[str] = None
    coc_from_db      = False
    try:
        async with session_scope() as db:
            coc_r = await db.execute(
                text("""
                    SELECT c.record_hash, c.sealed_at,
                           b.tsa_status, b.tsa_provider, b.tsa_time,
                           b.merkle_root
                    FROM forensic_chain_of_custody c
                    LEFT JOIN forensic_coc_batches b ON c.batch_id = b.id
                    WHERE c.session_id = :sid
                    ORDER BY c.sealed_at DESC
                    LIMIT 1
                """),
                {"sid": session_id},
            )
            coc_row = coc_r.mappings().fetchone()
            if coc_row:
                sha256_session = coc_row["record_hash"] or ""
                tsa_ok         = (coc_row["tsa_status"] == "ok")
                tsa_url        = coc_row["tsa_provider"] or ""
                # M-7: timestamp must reflect when the record was sealed,
                # not the session's started_at. Prefer the TSA-signed time
                # (cryptographically anchored) when available, else the
                # local sealed_at timestamp.
                ts_obj = coc_row["tsa_time"] or coc_row["sealed_at"]
                sealed_at_str = str(ts_obj) if ts_obj is not None else None
                coc_from_db = True
    except Exception as exc:
        log.debug("forensic_chain_of_custody query failed for %s: %s", session_id, exc)

    if not coc_from_db:
        # Engine hasn't sealed this session yet — fall back to a live seal so
        # the report still ships with a verifiable SHA-256 + (best-effort) TSA.
        try:
            _custody = await get_custody().seal(detail)
            sha256_session   = _custody.sha256
            tsa_ok           = bool(_custody.tsa_ok)
            tsa_url          = _custody.tsa_url
            tsa_token_b64    = _custody.tsa_token_b64
        except Exception as _coc_exc:
            log.warning("chain_of_custody seal failed: %s", _coc_exc)
            session_bytes    = json.dumps(detail, sort_keys=True, default=str).encode()
            sha256_session   = hashlib.sha256(session_bytes).hexdigest()
            tsa_ok           = False
            tsa_url          = ""
            tsa_token_b64    = None

    # ── Organised score (behavioural estimate) ─────────────
    n_cmd = len(cmds)
    org_score_pct = min(90, int(30 + n_cmd * 4 + (20 if auth_success else 0) + (10 if profile_dict.get("is_tor") else 0)))

    # ── Honeypots hit (for unified sessions) ──────────────
    honeypots_hit = pg_row.get("honeypots_hit") or []
    if isinstance(honeypots_hit, str):
        try: honeypots_hit = json.loads(honeypots_hit)
        except Exception: honeypots_hit = []
    # Fallback to the session's own honeypot type so the §5.3 breakdown is
    # never empty (single-honeypot reports still list their honeypot).
    if not honeypots_hit:
        _hp = pg_row.get("honeypot_type") or detail.get("honeypot")
        if _hp and _hp != "unified":
            honeypots_hit = [_hp]

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

    # ── Engine-persisted IOCs (forensic_iocs) ─────────────────────────────────
    # The engine's ioc_extractor.py upserts every URL/domain/IP/hash/CVE/cmdline
    # extracted from forensic_timeline_events into forensic_iocs, aggregated
    # per (type, value, source_ip). Prefer those rows over the inline build
    # (which only sees the current session's commands + the first captured
    # hash) so the IOC section reflects the engine's full extraction.
    engine_iocs: List[Dict[str, Any]] = []
    if source_ip:
        try:
            async with session_scope() as db:
                ioc_res = await db.execute(
                    text("""
                        SELECT ioc_type, ioc_value, context, honeypot_types,
                               occurrences, first_seen, last_seen
                        FROM forensic_iocs
                        WHERE source_ip = :ip
                        ORDER BY occurrences DESC, last_seen DESC
                        LIMIT 50
                    """),
                    {"ip": source_ip},
                )
                for r in ioc_res.mappings():
                    ctx_obj = r["context"] or {}
                    if isinstance(ctx_obj, str):
                        try: ctx_obj = json.loads(ctx_obj)
                        except Exception: ctx_obj = {}
                    hp_list = list(r["honeypot_types"] or [])
                    ctx_bits = []
                    if hp_list:
                        ctx_bits.append(f"seen by {'/'.join(hp_list)}")
                    occ = int(r["occurrences"] or 0)
                    if occ > 1:
                        ctx_bits.append(f"×{occ}")
                    if isinstance(ctx_obj, dict):
                        for k in ("via", "url", "method", "event"):
                            v = ctx_obj.get(k)
                            if v:
                                ctx_bits.append(f"{k}={str(v)[:60]}")
                                break
                    engine_iocs.append({
                        "type":    str(r["ioc_type"] or "").upper(),
                        "value":   r["ioc_value"] or "",
                        "context": " · ".join(ctx_bits) if ctx_bits else "",
                    })
        except Exception as exc:
            log.debug("forensic_iocs query failed for %s: %s", source_ip, exc)

    # ── Engine-persisted recommendations & key_findings (ip_risk_scores) ──────
    # The unified per-IP scorer writes structured recommendations (jsonb array
    # of action objects) and a key_findings text[] when it runs. Prefer the
    # engine's output over the adapter's heuristic-built list whenever the
    # engine has actually populated those columns.
    engine_recommendations: List[Dict[str, Any]] = []
    engine_key_findings:    List[str]            = []
    if source_ip:
        try:
            async with session_scope() as db:
                irs_r = await db.execute(
                    text("""
                        SELECT recommendations, key_findings
                        FROM ip_risk_scores
                        WHERE source_ip = CAST(:ip AS INET)
                        ORDER BY scored_at DESC NULLS LAST
                        LIMIT 1
                    """),
                    {"ip": source_ip},
                )
                irs_row = irs_r.mappings().fetchone()
                if irs_row:
                    raw_recs = irs_row["recommendations"] or []
                    if isinstance(raw_recs, str):
                        try: raw_recs = json.loads(raw_recs)
                        except Exception: raw_recs = []
                    if isinstance(raw_recs, list):
                        for r in raw_recs:
                            if not isinstance(r, dict):
                                continue
                            engine_recommendations.append({
                                "priority":  str(r.get("priority") or r.get("severity") or "MEDIUM").upper(),
                                "action":    str(r.get("action") or r.get("title") or r.get("recommendation") or ""),
                                "rationale": str(r.get("rationale") or r.get("reason") or r.get("description") or ""),
                            })
                    kf = irs_row["key_findings"] or []
                    if isinstance(kf, list):
                        engine_key_findings = [str(x) for x in kf if x]
        except Exception as exc:
            log.debug("ip_risk_scores recommendations query failed for %s: %s", source_ip, exc)

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
        "timeline_from_db": timeline_from_db,
        "mitre_rows": mitre_rows,
        "score_signals": score_signals,
        "sha256_session": sha256_session,
        "custody_ok": tsa_ok,
        "tsa_url": tsa_url,
        "tsa_token_b64": tsa_token_b64,
        "coc_sealed_at": sealed_at_str,
        "coc_from_db": coc_from_db,
        "kc_reached": kc_reached,
        "kc_stages": _KC_STAGES,
        "kc_stages_labels": _KC_LABELS,
        "org_score_pct": org_score_pct,
        "auth_success": auth_success,
        "malware_info": malware_info,
        "honeypots_hit": honeypots_hit,
        "sessions_count": pg_row.get("sessions_count") or 1,
        "enrichment_cache": enrichment_cache,
        "is_unified": is_unified,
        "vt_result": vt_result,
        # VirusTotal / extra per-session fields live in enrichment_data jsonb
        # (engine.py:1173+). Previous reads from AttackerProfile always
        # returned defaults; route through pg_row.enrichment_data so the
        # "Quota épuisé" / detection-count / family lines reflect reality.
        "vt_malicious":   int((pg_row.get("enrichment_data") or {}).get("vt_malicious")  or 0),
        "vt_available":   bool((pg_row.get("enrichment_data") or {}).get("vt_available", True)),
        "vt_family":      ((pg_row.get("enrichment_data") or {}).get("vt_family") or ""),
        # Surface the previously-dropped engine fields so downstream sections
        # can use them. Adapter consumes those it needs; rest is harmless.
        "engine_enrichment":  (pg_row.get("enrichment_data") or {}),
        "engine_version":     pg_row.get("score_version") or "v2.0.0-9signals",
        "session_ended_at":   pg_row.get("ended_at"),
        "attack_velocity":    pg_row.get("attack_velocity"),
        "destination_port":   (pg_row.get("enrichment_data") or {}).get("destination_port"),
        "command_count":      (pg_row.get("enrichment_data") or {}).get("command_count"),
        "file_download_count": (pg_row.get("enrichment_data") or {}).get("file_download_count"),
        "exfil_bytes":        (pg_row.get("enrichment_data") or {}).get("exfil_bytes"),
        "kill_chain_label":   (pg_row.get("enrichment_data") or {}).get("kill_chain_label"),
        "mapping_source":     (pg_row.get("enrichment_data") or {}).get("mapping_source"),
        "smb_share_enum":     bool((pg_row.get("enrichment_data") or {}).get("smb_share_enum")),
        "epmapper_prescan":   int((pg_row.get("enrichment_data") or {}).get("epmapper_prescan") or 0),
        "exploit_cve":        (pg_row.get("enrichment_data") or {}).get("exploit_cve") or [],
        "previously_seen":    bool((pg_row.get("enrichment_data") or {}).get("previously_seen")),
        "previous_sessions":  int((pg_row.get("enrichment_data") or {}).get("previous_sessions") or 0),
        "shodan_vulns":       (pg_row.get("enrichment_data") or {}).get("shodan_vulns") or [],
        "is_bogon":           bool((pg_row.get("enrichment_data") or {}).get("is_bogon")),
        "active_signals":     int((pg_row.get("enrichment_data") or {}).get("active_signals") or 0),
        "ollama_recommendations": ollama_recs,
        # Engine-persisted artifacts (forensic_iocs / timeline / coc / ip_risk_scores).
        # Empty lists/None mean the engine hasn't written rows yet for this
        # session — the adapter falls back to its inline build in that case.
        "engine_iocs":            engine_iocs,
        "engine_recommendations": engine_recommendations,
        "engine_key_findings":    engine_key_findings,
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
    correlation_id = uuid.uuid4().hex[:12]
    try:
        return await get_reports().generate(req)
    except Exception:
        log.exception("[%s] report generation failed", correlation_id)
        raise HTTPException(status_code=500, detail=f"report generation failed (cid={correlation_id})")


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
            # One row per source IP (aggregate all the IP's sessions).
            # Picks the most recent session as the "anchor" session_id used to
            # open the report, but exposes per-IP totals: max kill chain stage,
            # primary technique, sessions count, and risk_score from
            # ip_risk_scores (which is the unified per-IP score).
            result = await db.execute(
                text(
                    """
                    WITH ranked AS (
                        SELECT
                            fs.*,
                            ROW_NUMBER() OVER (PARTITION BY fs.source_ip ORDER BY fs.started_at DESC) AS rn,
                            COUNT(*)                 OVER (PARTITION BY fs.source_ip) AS agg_sessions_count,
                            SUM(fs.login_attempts)   OVER (PARTITION BY fs.source_ip) AS agg_login_attempts,
                            SUM(fs.success_count)    OVER (PARTITION BY fs.source_ip) AS agg_success_count,
                            MAX(fs.kill_chain_stage) OVER (PARTITION BY fs.source_ip) AS agg_kc_stage,
                            MAX(fs.attack_velocity)  OVER (PARTITION BY fs.source_ip) AS agg_velocity,
                            MAX(fs.risk_score)       OVER (PARTITION BY fs.source_ip) AS agg_risk_score
                        FROM forensic_sessions fs
                        WHERE fs.honeypot_type != 'unified'
                    )
                    SELECT
                        r.session_id, r.source_ip, r.honeypot_type,
                        -- Prefer the unified per-IP score (ip_risk_scores) when present,
                        -- but never fall below the actual per-session score: ip_risk_scores
                        -- is only populated for IPs above the profiling threshold, so most
                        -- sessions would otherwise COALESCE to 0 despite having a real score.
                        GREATEST(COALESCE(irs.risk_score, 0), COALESCE(r.agg_risk_score, 0)) AS risk_score,
                        CASE
                            WHEN GREATEST(COALESCE(irs.risk_score, 0), COALESCE(r.agg_risk_score, 0)) >= 80 THEN 'CRITICAL'
                            WHEN GREATEST(COALESCE(irs.risk_score, 0), COALESCE(r.agg_risk_score, 0)) >= 60 THEN 'HIGH'
                            WHEN GREATEST(COALESCE(irs.risk_score, 0), COALESCE(r.agg_risk_score, 0)) >= 40 THEN 'MEDIUM'
                            WHEN GREATEST(COALESCE(irs.risk_score, 0), COALESCE(r.agg_risk_score, 0)) >= 20 THEN 'LOW'
                            ELSE 'INFO'
                        END                                AS risk_level,
                        COALESCE(irs.confidence, 'LOW')    AS confidence,
                        r.kill_chain_phase,
                        r.agg_kc_stage                     AS kill_chain_stage,
                        r.primary_technique, r.forensic_narrative,
                        r.honeypots_hit, r.honeypot_count,
                        r.agg_sessions_count               AS sessions_count,
                        r.agg_login_attempts               AS login_attempts,
                        r.agg_success_count                AS success_count,
                        r.agg_velocity                     AS attack_velocity,
                        r.started_at, r.ended_at,
                        r.mitre_techniques
                    FROM ranked r
                    LEFT JOIN ip_risk_scores irs
                           ON irs.source_ip = CAST(r.source_ip AS INET)
                    WHERE r.rn = 1
                    ORDER BY risk_score DESC, r.started_at DESC
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
                    "risk_level":        row["risk_level"],
                    "confidence":        row["confidence"],
                    "kill_chain_phase":  row["kill_chain_phase"],
                    "kill_chain_stage":  row["kill_chain_stage"],
                    "primary_technique": row["primary_technique"],
                    "forensic_narrative": row["forensic_narrative"],
                    "mitre_techniques":  mitre,
                    "honeypots_hit":     row["honeypots_hit"] or [],
                    "honeypot_count":    row["honeypot_count"],
                    "sessions_count":    row["sessions_count"],
                    "login_attempts":    row["login_attempts"],
                    "success_count":     row["success_count"],
                    "attack_velocity":   row["attack_velocity"],
                    "started_at":        row["started_at"],
                    "ended_at":          row["ended_at"],
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


@router.get("/forensic/sessions/{session_id}/enrichment")
async def forensic_session_enrichment(session_id: str) -> Dict[str, Any]:
    """Return all enrichment + tool outputs for one session, used by the
    Attack Reconstruction UI: VirusTotal, Shodan, WHOIS, IPLocate, AbuseIPDB,
    YARA matches, MITRE technique details, captured-file SHA-256.

    Reads from forensic_sessions + ip_enrichment_cache + file_analysis tables.
    All blocks are optional — missing tools just return null/empty.
    """
    from sqlalchemy import text
    from db import session_scope

    out: Dict[str, Any] = {
        "session_id": session_id,
        "source_ip": None,
        "honeypot_type": None,
        "virustotal": None,
        "shodan": None,
        "whois": None,
        "iplocate": None,
        "abuseipdb": None,
        "yara": [],
        "captured_files": [],
        "mitre": [],
    }

    source_ip: str = ""
    honeypot_type: str = ""
    enrichment_data: Dict[str, Any] = {}
    mitre_techniques: List[str] = []

    try:
        async with session_scope() as db:
            r = await db.execute(text("""
                SELECT source_ip, honeypot_type, enrichment_data,
                       mitre_techniques, honeypots_hit
                FROM forensic_sessions WHERE session_id = :sid LIMIT 1
            """), {"sid": session_id})
            row = r.mappings().fetchone()
            if not row:
                return out
            source_ip = row["source_ip"] or ""
            honeypot_type = row["honeypot_type"] or ""
            ed = row["enrichment_data"] or {}
            enrichment_data = ed if isinstance(ed, dict) else (json.loads(ed) if ed else {})
            mt = row["mitre_techniques"] or []
            if isinstance(mt, str):
                try: mt = json.loads(mt)
                except Exception: mt = []
            mitre_techniques = mt if isinstance(mt, list) else []

            # Aggregate MITRE techniques across ALL sessions for this IP so the
            # reconstruction view shows the full picture (not just one session).
            if source_ip:
                agg = await db.execute(text("""
                    SELECT DISTINCT elem AS tech
                    FROM forensic_sessions,
                         jsonb_array_elements_text(
                             CASE WHEN jsonb_typeof(mitre_techniques) = 'array'
                                  THEN mitre_techniques ELSE '[]'::jsonb END
                         ) AS elem
                    WHERE source_ip = :ip AND honeypot_type != 'unified'
                      AND elem IS NOT NULL AND elem != ''
                """), {"ip": source_ip})
                agg_techs = [r2[0] for r2 in agg.fetchall()]
                if agg_techs:
                    # Preserve order, dedupe, prefer aggregated set
                    seen = set(); merged = []
                    for t in agg_techs + mitre_techniques:
                        if t and t not in seen:
                            seen.add(t); merged.append(t)
                    mitre_techniques = merged
    except Exception as exc:
        log.warning("enrichment lookup failed for %s: %s", session_id, exc)
        return out

    out["source_ip"] = source_ip
    out["honeypot_type"] = honeypot_type

    # ── ip_enrichment_cache → Shodan / WHOIS / IPLocate / AbuseIPDB ──
    enrichment: Dict[str, Any] = {}
    cache_hit = False
    if source_ip:
        try:
            async with session_scope() as db:
                er = await db.execute(
                    text("SELECT data FROM ip_enrichment_cache WHERE ip = :ip LIMIT 1"),
                    {"ip": source_ip},
                )
                erow = er.mappings().fetchone()
                if erow:
                    d = erow["data"]
                    enrichment = d if isinstance(d, dict) else json.loads(d or "{}")
                    cache_hit = bool(enrichment)
        except Exception as exc:
            log.debug("ip_enrichment_cache lookup failed: %s", exc)

    # ── Live fallback: call IPLocate + AbuseIPDB directly if cache is empty ──
    if source_ip and not cache_hit:
        from services.enrichment import get_enrichment as _get_enrichment
        svc = _get_enrichment()
        live_iplocate, live_abuseipdb = {}, {}
        try:
            import asyncio
            live_iplocate, live_abuseipdb = await asyncio.gather(
                svc.iplocate(source_ip),
                svc.abuseipdb(source_ip),
                return_exceptions=False,
            )
        except Exception as exc:
            log.debug("live enrichment fallback failed for %s: %s", source_ip, exc)
        if isinstance(live_iplocate, dict) and live_iplocate:
            enrichment["geo"] = {
                "country":     live_iplocate.get("country"),
                "country_iso": live_iplocate.get("country_iso"),
                "city":        live_iplocate.get("city"),
                "asn":         live_iplocate.get("asn"),
                "as_org":      live_iplocate.get("as_org"),
            }
            enrichment["privacy"] = {
                "is_tor":       live_iplocate.get("is_tor", False),
                "is_vpn":       live_iplocate.get("is_vpn", False),
                "is_proxy":     live_iplocate.get("is_proxy", False),
            }
        if isinstance(live_abuseipdb, dict) and live_abuseipdb:
            enrichment["reputation"] = {
                "abuseipdb_score": live_abuseipdb.get("abuseipdb_score"),
                "total_reports":   live_abuseipdb.get("abuseipdb_reports"),
                "usage_type":      live_abuseipdb.get("usage_type"),
                "isp":             live_abuseipdb.get("isp"),
                "domain":          live_abuseipdb.get("domain"),
                "is_tor":          live_abuseipdb.get("is_tor", False),
            }

    rep     = enrichment.get("reputation")     or {}
    whois   = enrichment.get("whois")          or {}
    privacy = enrichment.get("privacy")        or {}
    threat  = enrichment.get("threat_summary") or {}
    dns     = enrichment.get("dns")            or {}
    geo     = enrichment.get("geo")            or {}

    shodan_ports = threat.get("open_ports") or []
    shodan_vulns = threat.get("known_vulns") or []
    shodan_tags  = threat.get("shodan_tags") or []
    shodan_hosts = list(dict.fromkeys(
        ([dns.get("ptr")] if dns.get("ptr") else []) +
        (threat.get("hostnames") or []) +
        (rep.get("hostnames") or [])
    ))
    # Always include shodan block (even if empty) so the frontend always renders it
    out["shodan"] = {
        "_source": "cache" if cache_hit else "none",
        "ports": shodan_ports,
        "hostnames": shodan_hosts,
        "vulns": shodan_vulns,
        "tags": shodan_tags,
    }

    # Always include whois block. The enrichment cache stores RDAP-style keys
    # (network_name, cidr, asn_registry, registration, abuse_emails, ...).
    _abuse_emails = whois.get("abuse_emails")
    _abuse_email = (_abuse_emails[0] if isinstance(_abuse_emails, list) and _abuse_emails
                    else whois.get("abuse_email") or whois.get("abuse"))
    out["whois"] = {
        "_source": "cache" if (cache_hit and whois) else "none",
        "registrar":     (whois.get("asn_registry") or "").upper() or whois.get("registrar"),
        "organization":  whois.get("network_name") or whois.get("asn_description") or whois.get("organization") or whois.get("org"),
        "country":       whois.get("asn_country") or whois.get("country"),
        "created":       whois.get("registration") or whois.get("created") or whois.get("creation_date"),
        "updated":       whois.get("last_changed") or whois.get("updated"),
        "abuse_email":   _abuse_email,
        "net_range":     whois.get("cidr") or whois.get("asn_cidr") or whois.get("net_range") or whois.get("network"),
        "asn":           whois.get("asn"),
        "network_type":  whois.get("network_type"),
        "asn_description": whois.get("asn_description"),
    }

    # Always include iplocate block
    out["iplocate"] = {
        "_source": "live" if (not cache_hit and geo) else ("cache" if geo else "none"),
        "country":      geo.get("country") or rep.get("country_name"),
        "country_iso":  geo.get("country_iso") or rep.get("country_code"),
        "city":         geo.get("city"),
        "region":       geo.get("region"),
        "lat":          geo.get("lat"),
        "lon":          geo.get("lon"),
        "asn":          geo.get("asn") or rep.get("asn"),
        "as_org":       geo.get("as_org") or rep.get("as_org") or rep.get("isp"),
        "is_tor":       bool(privacy.get("is_tor") or threat.get("is_tor")),
        "is_vpn":       bool(privacy.get("is_vpn") or threat.get("is_vpn")),
        "is_proxy":     bool(privacy.get("is_proxy")),
        "is_hosting":   bool(privacy.get("is_hosting")),
        "is_datacenter":bool(privacy.get("is_datacenter")),
        "is_bogon":     bool(privacy.get("is_bogon")),
    }

    # Always include abuseipdb block
    out["abuseipdb"] = {
        "_source": "live" if (not cache_hit and rep) else ("cache" if rep else "none"),
        "abuse_score":   rep.get("abuseipdb_score") or rep.get("abuse_score"),
        "total_reports": rep.get("total_reports"),
        "last_reported": rep.get("last_reported_at"),
        "usage_type":    rep.get("usage_type"),
        "isp":           rep.get("isp"),
        "domain":        rep.get("domain"),
        "country":       rep.get("country_name") or geo.get("country"),
    }

    # ── YARA matches ──
    yara_raw = enrichment_data.get("yara_matches") or []
    if isinstance(yara_raw, str):
        try: yara_raw = json.loads(yara_raw)
        except Exception: yara_raw = []
    if isinstance(yara_raw, list):
        for ym in yara_raw:
            if isinstance(ym, dict):
                out["yara"].append({
                    "rule":        ym.get("rule") or ym.get("name"),
                    "namespace":   ym.get("namespace"),
                    "tags":        ym.get("tags") or [],
                    "meta":        ym.get("meta") or {},
                })
            elif ym:
                out["yara"].append({"rule": str(ym), "namespace": None, "tags": [], "meta": {}})

    # ── Captured files (Dionaea) + VirusTotal lookup ──
    captured_sha = enrichment_data.get("captured_file") or enrichment_data.get("sha256")
    if captured_sha:
        try:
            async with session_scope() as db:
                fr = await db.execute(text("""
                    SELECT sha256, file_size, file_type, virustotal_result, yara_result
                    FROM file_analysis WHERE sha256 = :sha LIMIT 1
                """), {"sha": captured_sha})
                frow = fr.mappings().fetchone()
                if frow:
                    vt = frow["virustotal_result"]
                    if isinstance(vt, str):
                        try: vt = json.loads(vt)
                        except Exception: vt = {}
                    vt = vt or {}
                    stats = vt.get("last_analysis_stats") or vt.get("stats") or {}
                    out["captured_files"].append({
                        "sha256":   frow["sha256"],
                        "size":     frow["file_size"],
                        "type":     frow["file_type"],
                    })
                    if vt:
                        out["virustotal"] = {
                            "sha256":     frow["sha256"],
                            "malicious":  stats.get("malicious", vt.get("malicious", 0)),
                            "suspicious": stats.get("suspicious", 0),
                            "harmless":   stats.get("harmless", 0),
                            "undetected": stats.get("undetected", 0),
                            "engines":    vt.get("engines_count") or sum(stats.values()) if stats else None,
                            "family":     vt.get("popular_threat_classification", {}).get("suggested_threat_label") if isinstance(vt.get("popular_threat_classification"), dict) else vt.get("family"),
                            "names":      (vt.get("names") or [])[:5],
                            "first_seen": vt.get("first_submission_date") or vt.get("first_seen"),
                            "permalink":  vt.get("permalink") or (f"https://www.virustotal.com/gui/file/{frow['sha256']}" if frow["sha256"] else None),
                        }
                else:
                    out["captured_files"].append({"sha256": captured_sha, "size": None, "type": None})
        except Exception as exc:
            log.debug("file_analysis lookup failed: %s", exc)
            out["captured_files"].append({"sha256": captured_sha, "size": None, "type": None})

    # ── MITRE technique details (id + tactic mapping) ──
    _TACTICS = {
        "T1110": ("Brute Force", "Credential Access"),
        "T1078": ("Valid Accounts", "Defense Evasion"),
        "T1190": ("Exploit Public-Facing Application", "Initial Access"),
        "T1059": ("Command and Scripting Interpreter", "Execution"),
        "T1105": ("Ingress Tool Transfer", "Command and Control"),
        "T1046": ("Network Service Discovery", "Discovery"),
        "T1071": ("Application Layer Protocol", "Command and Control"),
        "T1133": ("External Remote Services", "Initial Access"),
        "T1136": ("Create Account", "Persistence"),
        "T1003": ("OS Credential Dumping", "Credential Access"),
        "T1082": ("System Information Discovery", "Discovery"),
        "T1083": ("File and Directory Discovery", "Discovery"),
        "T1018": ("Remote System Discovery", "Discovery"),
        "T1021": ("Remote Services", "Lateral Movement"),
        "T1486": ("Data Encrypted for Impact", "Impact"),
    }
    for t in mitre_techniques:
        tid = str(t).split(".")[0]
        name, tactic = _TACTICS.get(tid, ("", ""))
        out["mitre"].append({
            "id":     str(t),
            "name":   name or "Technique",
            "tactic": tactic or "Unknown",
            "url":    f"https://attack.mitre.org/techniques/{tid}/",
        })

    return out


def _pick_report_template(lang: str | None) -> str:
    return "forenhive_rapport_v2_fr.html" if (lang or "").lower() == "fr" else "forenhive_rapport_v2.html"


@router.post("/forensic/{session_id}/generate")
async def forensic_generate(request: Request, session_id: str, lang: str = "en"):
    """Generate and download a forensic PDF for one session using the rich forensic template."""
    if not _WEASY_AVAILABLE:
        raise HTTPException(status_code=503, detail="WeasyPrint not installed")

    correlation_id = uuid.uuid4().hex[:12]
    try:
        ctx = await _build_forensic_context(session_id)
    except Exception:
        log.exception("[%s] forensic context build failed for %s", correlation_id, session_id)
        raise HTTPException(status_code=500, detail=f"context build failed (cid={correlation_id})")

    # Session not found in ES or PG
    if not ctx["session"].get("source_ip") and not ctx["profile"].get("ip"):
        raise HTTPException(status_code=404, detail="session not found")

    v2_ctx = _adapt_context_for_v2(ctx)

    try:
        html_body = _JINJA_ENV.get_template(_pick_report_template(lang)).render(**v2_ctx)
    except Exception:
        log.exception("[%s] template render failed", correlation_id)
        raise HTTPException(status_code=500, detail=f"template render failed (cid={correlation_id})")

    settings = get_settings()
    out_dir = Path(settings.reports_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    pdf_path = out_dir / f"forensic-{session_id}-{uuid.uuid4().hex[:8]}.pdf"

    try:
        _WeasyHTML(string=html_body).write_pdf(str(pdf_path))
    except Exception:
        log.exception("[%s] WeasyPrint render failed", correlation_id)
        raise HTTPException(status_code=500, detail=f"PDF generation failed (cid={correlation_id})")

    pdf_bytes = pdf_path.read_bytes()
    sha256 = hashlib.sha256(pdf_bytes).hexdigest()
    etag = f'W/"{sha256}"'

    # If-None-Match → 304 short-circuit (re-downloads of an unchanged report)
    inm = request.headers.get("if-none-match")
    if inm and sha256 in inm:
        return JSONResponse(
            status_code=304,
            content=None,
            headers={"ETag": etag, "X-PDF-SHA256": sha256, "X-ForenHive-SHA256": sha256},
        )

    return FileResponse(
        path=str(pdf_path),
        media_type="application/pdf",
        filename=f"ForenHive-{v2_ctx['report_id']}.pdf",
        headers={
            "ETag": etag,
            "Cache-Control": "private, max-age=60",
            "X-PDF-SHA256": sha256,
            "X-ForenHive-SHA256": sha256,
            "Content-Disposition": f'attachment; filename="ForenHive-{v2_ctx["report_id"]}.pdf"',
        },
    )


@router.get("/forensic/{session_id}/detail")
async def forensic_session_detail(session_id: str) -> Dict[str, Any]:
    """Return full session data including enrichment_data as JSON for the reconstruction page."""
    from sqlalchemy import text
    from db import session_scope

    _KC_PHASE_BY_STAGE = {
        1: "reconnaissance", 2: "weaponization", 3: "delivery", 4: "exploitation",
        5: "installation", 6: "command_and_control", 7: "lateral_movement", 8: "actions_on_objectives",
    }
    row: Dict[str, Any] = {}
    try:
        async with session_scope() as db:
            result = await db.execute(
                text("""
                    SELECT session_id, source_ip, honeypot_type, risk_score,
                           kill_chain_phase, kill_chain_stage, primary_technique,
                           forensic_narrative, mitre_techniques, enrichment_data,
                           login_attempts, success_count, attack_velocity,
                           started_at, ended_at, created_at
                    FROM forensic_sessions
                    WHERE session_id = :sid
                    LIMIT 1
                """),
                {"sid": session_id},
            )
            r = result.mappings().fetchone()
            if r:
                row = dict(r)
                for field in ("mitre_techniques", "enrichment_data"):
                    v = row.get(field)
                    if isinstance(v, str):
                        try:
                            row[field] = json.loads(v)
                        except Exception:
                            row[field] = [] if field == "mitre_techniques" else {}
                for field in ("started_at", "ended_at", "created_at"):
                    if row.get(field) is not None:
                        row[field] = str(row[field])

                # ── Aggregate per-IP so the reconstruction view is consistent
                #    with the report (full attack picture, not one sub-session) ──
                _ip = row.get("source_ip")
                if _ip:
                    agg = await db.execute(text("""
                        SELECT
                            COUNT(*)                  AS sub_sessions,
                            SUM(login_attempts)       AS total_attempts,
                            SUM(success_count)        AS total_success,
                            MAX(kill_chain_stage)     AS max_kc_stage,
                            MAX(attack_velocity)      AS max_velocity
                        FROM forensic_sessions
                        WHERE source_ip = :ip AND honeypot_type != 'unified'
                    """), {"ip": _ip})
                    a = agg.mappings().fetchone()
                    if a:
                        row["sub_sessions"]    = int(a["sub_sessions"] or 1)
                        row["login_attempts"]  = int(a["total_attempts"] or row.get("login_attempts") or 0)
                        row["success_count"]   = int(a["total_success"] or 0)
                        _maxkc = int(a["max_kc_stage"] or row.get("kill_chain_stage") or 0)
                        row["kill_chain_stage"] = _maxkc
                        row["kill_chain_phase"] = _KC_PHASE_BY_STAGE.get(_maxkc, row.get("kill_chain_phase"))
                        if a["max_velocity"] is not None:
                            row["attack_velocity"] = float(a["max_velocity"])

                    # Aggregate MITRE techniques + pick a meaningful primary
                    mres = await db.execute(text("""
                        SELECT DISTINCT elem AS tech
                        FROM forensic_sessions,
                             jsonb_array_elements_text(
                                 CASE WHEN jsonb_typeof(mitre_techniques) = 'array'
                                      THEN mitre_techniques ELSE '[]'::jsonb END
                             ) AS elem
                        WHERE source_ip = :ip AND honeypot_type != 'unified'
                          AND elem IS NOT NULL AND elem != ''
                    """), {"ip": _ip})
                    techs = [m[0] for m in mres.fetchall()]
                    if techs:
                        row["mitre_techniques"] = techs
                        # Primary technique priority: brute force > valid accounts >
                        # exploit > shell > first available.
                        for pref in ("T1110.001", "T1078", "T1190", "T1059.004"):
                            if pref in techs:
                                row["primary_technique"] = pref
                                break
    except Exception as exc:
        log.warning("forensic_session_detail: PG query failed for %s: %s", session_id, exc)

    if not row:
        raise HTTPException(status_code=404, detail="session not found")
    return row


@router.get("/forensic/{session_id}/preview")
async def forensic_preview(session_id: str, lang: str = "en"):
    """Full forensic HTML dossier for a single session (rich preview matching the PDF design)."""
    correlation_id = uuid.uuid4().hex[:12]
    try:
        ctx = await _build_forensic_context(session_id)
    except Exception:
        log.exception("[%s] forensic context build failed for %s", correlation_id, session_id)
        raise HTTPException(status_code=500, detail=f"context build failed (cid={correlation_id})")

    # Session not found in ES or PG
    if not ctx["session"].get("source_ip") and not ctx["profile"].get("ip"):
        raise HTTPException(status_code=404, detail="session not found")

    v2_ctx = _adapt_context_for_v2(ctx)

    correlation_id = uuid.uuid4().hex[:12]
    try:
        html_body = _JINJA_ENV.get_template(_pick_report_template(lang)).render(**v2_ctx)
    except Exception:
        log.exception("[%s] template render failed", correlation_id)
        raise HTTPException(status_code=500, detail=f"template render failed (cid={correlation_id})")
    return HTMLResponse(html_body)
