"""
ForenHive Risk Scoring v2.0.0 — 9-signal model.

Signal taxonomy (mapped to FBI BAU criminology framework):
  WHO  (33): reputation - anonymization - threat_history
  WHAT (43): intent_volume - compromise_depth - exfiltration - lateral_movement
  HOW  (24): malware - mitre_sophistication
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from math import log2, log10

from risk_thresholds import risk_level

log = logging.getLogger("risk_score")

SCORE_VERSION = "2.0.0"

# Constants used by signals
_SANCTIONED_CC = {"KP", "IR", "SY", "CU", "VE"}
_HIGH_THREAT_CC = {"RU", "CN", "BY"}
_CRITICAL_PORTS = {445, 1433, 3306, 3389, 5432, 27017, 6379, 9200}
_SCAN_PATHS = [
    "/admin",
    "/wp-admin",
    "/.env",
    "/phpmyadmin",
    "/.git",
    "/config",
    "/backup",
    "/.htaccess",
    "/wp-login.php",
    "/phpinfo.php",
    "/.well-known",
    "/api/",
    "/swagger",
]
_CRED_PATTERNS = [
    "/etc/shadow",
    "/etc/passwd",
    ".ssh/id_rsa",
    ".ssh/authorized_keys",
    ".bash_history",
    ".aws/credentials",
    "env | grep",
    "printenv",
    "cat /root/",
    "cat /home/",
    "mimikatz",
]
_DESTRUCTIVE_PATTERNS = [
    "rm -rf",
    "iptables -F",
    "chmod 777",
    ":(){:|:&};:",
    "dd if=/dev/zero",
    "mkfs.",
    "shred -",
]
_LATERAL_PATTERNS = [
    "ssh ",
    "scp ",
    "psexec",
    "wmic ",
    "nc -e",
    "ncat -e",
    "/usr/bin/ssh",
    "sshpass",
]
_TACTIC_OF = {
    "T1110.001": "credential_access",
    "T1110.003": "credential_access",
    "T1078": "initial_access",
    "T1059.004": "execution",
    "T1105": "command_and_control",
    "T1552.001": "credential_access",
    "T1210": "lateral_movement",
    "T1190": "initial_access",
    "T1595.002": "reconnaissance",
    "T1046": "discovery",
    "T1021.002": "lateral_movement",
    "T1486": "impact",
    "T1496": "impact",
    "T1071.001": "command_and_control",
    "T1592": "reconnaissance",
}

_SEV_TO_PTS = {"critical": 6, "high": 4, "medium": 2, "low": 1}


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _clamp(v, lo, hi):
    return max(lo, min(hi, v))


def _coerce_int(v, default=0):
    try:
        return int(v) if v is not None else default
    except (TypeError, ValueError):
        return default


def _coerce_float(v, default=0.0):
    try:
        return float(v) if v is not None else default
    except (TypeError, ValueError):
        return default


@dataclass
class SignalDetail:
    points: float
    max_points: int
    label: str
    category: str  # "who" | "what" | "how"
    detail: str  # human one-liner
    evidence: dict = field(default_factory=dict)
    skipped: bool = False
    skip_reason: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScoreResult:
    risk_score: int
    risk_level: str
    confidence: str
    score_version: str
    scored_at: str
    scorer_mode: str  # "session" | "ip_aggregate"
    signal_breakdown: dict
    active_signals: int
    sessions_aggregated: int | None = None

    def to_dict(self) -> dict:
        return asdict(self)


# ── Signal 1: reputation (WHO, max 15) ────────────────────────────────────────
def _signal_reputation(d: dict) -> SignalDetail:
    if bool(d.get("is_private")):
        return SignalDetail(
            0,
            15,
            "reputation",
            "who",
            "private IP — reputation N/A",
            skipped=True,
            skip_reason="private_ip",
        )
    abuse = _clamp(_coerce_int(d.get("abuse_score")), 0, 100)
    if abuse >= 90:
        pts, tag = 15, "critical"
    elif abuse >= 70:
        pts, tag = 11, "high"
    elif abuse >= 50:
        pts, tag = 7, "elevated"
    elif abuse >= 25:
        pts, tag = 4, "low"
    else:
        pts, tag = 0, "clean"
    evidence = {}
    if pts > 0:
        evidence = {
            "abuse_score": abuse,
            "total_reports": _coerce_int(d.get("abuse_total_reports")),
            "distinct_users": _coerce_int(d.get("abuse_distinct_users")),
            "categories": list(d.get("abuse_categories") or []),
        }
    return SignalDetail(
        pts, 15, "reputation", "who", f"AbuseIPDB {abuse}/100 — {tag}", evidence=evidence
    )


# ── Signal 2: anonymization (WHO, max 10) ─────────────────────────────────────
def _signal_anonymization(d: dict) -> SignalDetail:
    if bool(d.get("is_private")):
        return SignalDetail(
            0,
            10,
            "anonymization",
            "who",
            "private IP — anonymization N/A",
            skipped=True,
            skip_reason="private_ip",
        )
    is_bogon = bool(d.get("is_bogon"))
    is_tor = bool(d.get("is_tor"))
    is_vpn = bool(d.get("is_vpn"))
    is_proxy = bool(d.get("is_proxy"))
    is_datacenter = bool(d.get("is_datacenter"))

    if is_bogon:
        pts, tag = 10, "bogon"
    elif is_tor:
        pts, tag = 10, "Tor"
    elif is_vpn or is_proxy:
        pts, tag = 6, "VPN/proxy"
    elif is_datacenter:
        pts, tag = 3, "datacenter ASN"
    else:
        pts, tag = 0, "direct"

    evidence = {
        "is_bogon": is_bogon,
        "is_tor": is_tor,
        "is_vpn": is_vpn,
        "is_proxy": is_proxy,
        "is_datacenter": is_datacenter,
        "asn": _coerce_int(d.get("geo_asn")),
        "org": str(d.get("geo_org") or ""),
    }
    return SignalDetail(pts, 10, "anonymization", "who", f"anonymization: {tag}", evidence=evidence)


# ── Signal 3: threat_history (WHO, max 8) ─────────────────────────────────────
def _signal_threat_history(d: dict) -> SignalDetail:
    pts = 0
    reasons = []

    prev_seen = bool(d.get("previously_seen"))
    prev_n = max(0, _coerce_int(d.get("previous_sessions")))
    if prev_seen and prev_n > 0:
        rec_pts = min(4, int(2 * log2(1 + prev_n)))
        if rec_pts > 0:
            pts += rec_pts
            reasons.append(f"recidivism ({prev_n} prior)")

    if bool(d.get("is_abuser_listed")):
        pts += 1
        reasons.append("abuser-listed")

    if str(d.get("threat_tier") or "").lower() == "high":
        pts += 1
        reasons.append("threat-tier high")

    cc = str(d.get("geo_country_code") or "").upper()
    if cc in _SANCTIONED_CC:
        pts += 2
        reasons.append(f"sanctioned CC {cc}")
    elif cc in _HIGH_THREAT_CC:
        pts += 1
        reasons.append(f"high-threat CC {cc}")

    shodan_vulns = list(d.get("shodan_vulns") or [])
    if shodan_vulns:
        vp = min(2, len(shodan_vulns))
        pts += vp
        reasons.append(f"{len(shodan_vulns)} shodan vulns")

    pts = min(8, pts)
    detail = " - ".join(reasons) if reasons else "no prior history"
    evidence = {
        "previously_seen": prev_seen,
        "previous_sessions": prev_n,
        "is_abuser_listed": bool(d.get("is_abuser_listed")),
        "threat_tier": str(d.get("threat_tier") or ""),
        "geo_country_code": cc,
        "shodan_vulns": shodan_vulns,
    }
    return SignalDetail(pts, 8, "threat_history", "who", detail, evidence=evidence)


# ── Signal 4: intent_volume (WHAT, max 10) ────────────────────────────────────
def _signal_intent_volume(d: dict) -> SignalDetail:
    hp = str(d.get("honeypot_type") or "")
    attempts = max(0, _coerce_int(d.get("login_attempts")))
    velocity = max(0.0, _coerce_float(d.get("attack_velocity")))

    effective = attempts if hp == "cowrie" else attempts * 0.5
    base = min(6, int(2 * log10(1 + effective)))
    vel_bonus = 2 if velocity > 50 else (1 if velocity > 10 else 0)

    haystack_parts = []
    for p in d.get("http_paths") or []:
        haystack_parts.append(str(p).lower())
    for c in d.get("commands") or []:
        haystack_parts.append(str(c).lower())
    haystack = " ".join(haystack_parts)
    scan_hits = [p for p in _SCAN_PATHS if p in haystack]
    path_bonus = min(3, len(scan_hits))

    pts = min(10, base + vel_bonus + path_bonus)
    evidence = {
        "login_attempts": attempts,
        "attack_velocity": round(velocity, 2),
        "honeypot_type": hp,
        "scan_paths_hit": scan_hits,
    }
    detail = f"{attempts} attempts @ {round(velocity, 2)}/s" + (
        f" - {len(scan_hits)} scan paths" if scan_hits else ""
    )
    return SignalDetail(pts, 10, "intent_volume", "what", detail, evidence=evidence)


# ── Signal 5: compromise_depth (WHAT, max 15) ─────────────────────────────────
def _signal_compromise_depth(d: dict) -> SignalDetail:
    success = max(0, _coerce_int(d.get("success_count")))
    cmds_count = max(0, _coerce_int(d.get("command_count")))
    cmds_list = list(d.get("commands") or [])
    files_in = max(0, _coerce_int(d.get("file_download_count")))

    if success == 0 and files_in == 0:
        return SignalDetail(0, 15, "compromise_depth", "what", "no successful authentication")

    auth_pts = int(5 * log2(1 + success)) if success > 0 else 0
    cmd_vol_pts = min(3, cmds_count // 3)

    # Command quality: prefer pre-aggregated tags (IP-mode) over pattern matching.
    # Per-session callers don't set this key, so we fall through to pattern logic.
    precomputed_tags = list(d.get("command_quality_tags") or [])
    if precomputed_tags:
        quality_tags = precomputed_tags
        quality_pts = 0
        if "credential-access" in precomputed_tags:
            quality_pts += 3
        if "destructive" in precomputed_tags:
            quality_pts += 2
        if "lateral-cmd" in precomputed_tags:
            quality_pts += 1
        quality_pts = min(4, quality_pts)
    else:
        cmd_blob = " ".join(str(c).lower() for c in cmds_list)
        quality_pts = 0
        quality_tags = []
        if any(p in cmd_blob for p in _CRED_PATTERNS):
            quality_pts += 3
            quality_tags.append("credential-access")
        if any(p in cmd_blob for p in _DESTRUCTIVE_PATTERNS):
            quality_pts += 2
            quality_tags.append("destructive")
        if any(p in cmd_blob for p in _LATERAL_PATTERNS):
            quality_pts += 1
            quality_tags.append("lateral-cmd")
        quality_pts = min(4, quality_pts)

    ingress_pts = min(3, files_in)
    pts = min(15, auth_pts + cmd_vol_pts + quality_pts + ingress_pts)

    sample = [str(c) for c in cmds_list[:5]]
    evidence = {
        "success_count": success,
        "command_count": cmds_count,
        "command_quality_tags": quality_tags,
        "file_download_count": files_in,
        "sample_commands": sample,
    }
    parts = []
    if success > 0:
        parts.append(f"{success} successful auth")
    if cmds_count > 0:
        parts.append(f"{cmds_count} commands")
    if quality_tags:
        parts.append("/".join(quality_tags))
    if files_in > 0:
        parts.append(f"{files_in} file(s) ingressed")
    detail = " - ".join(parts) if parts else "compromise observed"
    return SignalDetail(pts, 15, "compromise_depth", "what", detail, evidence=evidence)


# ── Signal 6: exfiltration (WHAT, max 8) ──────────────────────────────────────
def _signal_exfiltration(d: dict) -> SignalDetail:
    bytes_out = max(0, _coerce_int(d.get("exfil_bytes")))
    kb = bytes_out / 1024.0
    pts = min(8, int(2 * log10(1 + kb)))
    if pts == 0:
        return SignalDetail(
            0,
            8,
            "exfiltration",
            "what",
            "no data egress observed",
            evidence={"exfil_bytes": bytes_out, "exfil_kb": round(kb, 1)},
        )
    if kb < 1024:
        size_str = f"{kb:.1f} KB"
    elif kb < 1024 * 1024:
        size_str = f"{kb / 1024:.1f} MB"
    else:
        size_str = f"{kb / (1024 * 1024):.1f} GB"
    return SignalDetail(
        pts,
        8,
        "exfiltration",
        "what",
        f"egress {size_str}",
        evidence={"exfil_bytes": bytes_out, "exfil_kb": round(kb, 1)},
    )


# ── Signal 7: lateral_movement (WHAT, max 10) ─────────────────────────────────
def _signal_lateral_movement(d: dict) -> SignalDetail:
    exploit_cve = list(d.get("exploit_cve") or [])
    share_enum = bool(d.get("smb_share_enum"))
    epmapper = max(0, _coerce_int(d.get("epmapper_prescan")))
    honeypot_hit = list(set(d.get("honeypot_types_hit") or []))
    nh = len(honeypot_hit)
    dest_port = _coerce_int(d.get("destination_port"))

    pts = 0
    reasons = []
    if exploit_cve:
        pts += 4
        reasons.append(f"CVE exploit ({len(exploit_cve)})")
    if share_enum:
        pts += 2
        reasons.append("SMB share enum")
    if epmapper > 0:
        pts += 2
        reasons.append(f"epmapper prescan ({epmapper})")
    if nh >= 3:
        pts += 2
        reasons.append(f"{nh} honeypots hit")
    elif nh >= 2:
        pts += 1
        reasons.append(f"{nh} honeypots hit")
    crit_port_evidence = None
    if dest_port in _CRITICAL_PORTS:
        pts += 2
        reasons.append(f"critical port {dest_port}")
        crit_port_evidence = dest_port

    pts = min(10, pts)
    evidence = {
        "exploit_cve": exploit_cve,
        "smb_share_enum": share_enum,
        "epmapper_prescan": epmapper,
        "honeypot_types_hit": honeypot_hit,
        "destination_port": crit_port_evidence,
    }
    detail = " - ".join(reasons) if reasons else "no lateral indicators"
    return SignalDetail(pts, 10, "lateral_movement", "what", detail, evidence=evidence)


# ── Signal 8: malware (HOW, max 12) ───────────────────────────────────────────
def _signal_malware(d: dict) -> SignalDetail:
    yara_raw = list(d.get("yara_matches") or [])
    vt = max(0, _coerce_int(d.get("vt_malicious")))

    # Normalize YARA to [{rule, severity}, ...], accepting legacy [str].
    yara_norm = []
    for m in yara_raw:
        if isinstance(m, dict):
            rule = m.get("rule", "")
            sev = str(m.get("severity") or "medium").lower()
            yara_norm.append({"rule": rule, "severity": sev})
        elif isinstance(m, str):
            yara_norm.append({"rule": m, "severity": "medium"})

    yara_pts = 0
    top_rule = ""
    top_sev = ""
    for m in yara_norm:
        sp = _SEV_TO_PTS.get(m["severity"], 1)
        if sp > yara_pts:
            yara_pts = sp
            top_rule = m["rule"]
            top_sev = m["severity"]

    if vt >= 20:
        vt_pts, vt_tag = 6, "very-high"
    elif vt >= 10:
        vt_pts, vt_tag = 4, "high"
    elif vt >= 1:
        vt_pts, vt_tag = 2, "low"
    else:
        vt_pts, vt_tag = 0, "clean"

    pts = min(12, yara_pts + vt_pts)
    parts = []
    if yara_pts > 0:
        parts.append(f"YARA {top_rule} ({top_sev})")
    if vt_pts > 0:
        parts.append(f"VT {vt} engines [{vt_tag}]")
    detail = " - ".join(parts) if parts else "no malware indicators"
    evidence = {
        "yara_matches": yara_norm,
        "vt_malicious": vt,
        "vt_family": str(d.get("vt_family") or ""),
    }
    return SignalDetail(pts, 12, "malware", "how", detail, evidence=evidence)


# ── Signal 9: mitre_sophistication (HOW, max 12) ──────────────────────────────
def _signal_mitre_sophistication(d: dict) -> SignalDetail:
    techniques = list(d.get("mitre_techniques") or [])
    tech_ids = []
    for t in techniques:
        if isinstance(t, dict):
            tid = t.get("id") or t.get("technique_id")
            if tid:
                tech_ids.append(str(tid))
        elif isinstance(t, str):
            tech_ids.append(t)
    tech_ids_unique = sorted(set(tech_ids))

    stage = max(0, _coerce_int(d.get("kill_chain_stage")))

    tech_pts = min(6, len(tech_ids_unique))
    stage_pts = min(4, stage // 2)
    tactics = {_TACTIC_OF.get(t) for t in tech_ids_unique if _TACTIC_OF.get(t)}
    tactics.discard(None)
    tactic_pts = min(2, max(0, len(tactics) - 1))

    pts = min(12, tech_pts + stage_pts + tactic_pts)
    detail = f"{len(tech_ids_unique)} technique(s), {len(tactics)} tactic(s), stage {stage}"
    evidence = {
        "mitre_techniques": tech_ids_unique,
        "kill_chain_stage": stage,
        "kill_chain_phase": str(d.get("kill_chain_phase") or ""),
        "distinct_tactics": sorted(tactics),
    }
    return SignalDetail(pts, 12, "mitre_sophistication", "how", detail, evidence=evidence)


# ── Orchestrator: per-session scoring ─────────────────────────────────────────
_SIGNALS = [
    ("reputation", _signal_reputation),
    ("anonymization", _signal_anonymization),
    ("threat_history", _signal_threat_history),
    ("intent_volume", _signal_intent_volume),
    ("compromise_depth", _signal_compromise_depth),
    ("exfiltration", _signal_exfiltration),
    ("lateral_movement", _signal_lateral_movement),
    ("malware", _signal_malware),
    ("mitre_sophistication", _signal_mitre_sophistication),
]


def score_session(session_data: dict) -> ScoreResult:
    """Score a single session against 9 signals. Returns ScoreResult."""
    if not isinstance(session_data, dict):
        session_data = {}

    breakdown = {}
    total = 0.0
    active = 0
    for sid, fn in _SIGNALS:
        try:
            sig = fn(session_data)
        except Exception as e:
            log.warning(f"signal {sid} raised: {e}")
            sig = SignalDetail(0, 0, sid, "?", f"error: {e}", skipped=True, skip_reason="exception")
        breakdown[sid] = sig.to_dict()
        total += sig.points
        if sig.points > 0:
            active += 1

    score_int = min(100, int(round(total)))
    if active >= 5:
        confidence = "HIGH"
    elif active >= 3:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    return ScoreResult(
        risk_score=score_int,
        risk_level=risk_level(score_int),
        confidence=confidence,
        score_version=SCORE_VERSION,
        scored_at=_now_iso(),
        scorer_mode="session",
        signal_breakdown=breakdown,
        active_signals=active,
        sessions_aggregated=None,
    )


# ── Orchestrator: per-IP aggregate scoring ────────────────────────────────────
def _empty_ip_result() -> ScoreResult:
    breakdown = {
        sid: SignalDetail(
            0, 0, sid, "?", "no sessions", skipped=True, skip_reason="empty_aggregate"
        ).to_dict()
        for sid, _ in _SIGNALS
    }
    return ScoreResult(
        risk_score=0,
        risk_level="INFO",
        confidence="LOW",
        score_version=SCORE_VERSION,
        scored_at=_now_iso(),
        scorer_mode="ip_aggregate",
        signal_breakdown=breakdown,
        active_signals=0,
        sessions_aggregated=0,
    )


def score_ip(source_ip: str, sessions: list, enrichment: dict) -> ScoreResult:
    """Score one IP by aggregating across its sessions + IP-level enrichment."""
    if not sessions:
        return _empty_ip_result()

    enrichment = enrichment if isinstance(enrichment, dict) else {}
    reputation = enrichment.get("reputation") or {}
    enrichment.get("privacy") or {}
    threat = enrichment.get("threat_summary") or {}
    geo = enrichment.get("geo") or {}
    infra = enrichment.get("infrastructure") or {}

    # WHO fields from enrichment
    super_session = {
        "is_private": False,
        "abuse_score": reputation.get("abuse_score", 0),
        "abuse_total_reports": reputation.get("total_reports", 0),
        "abuse_distinct_users": reputation.get("distinct_users", 0),
        "abuse_categories": threat.get("attack_categories", []),
        "is_tor": threat.get("is_tor", False),
        "is_vpn": threat.get("is_vpn", False),
        "is_proxy": threat.get("is_proxy", False),
        "is_datacenter": threat.get("is_datacenter", False),
        "is_bogon": threat.get("is_bogon", False),
        "is_abuser_listed": threat.get("is_abuser_listed", False),
        "threat_tier": threat.get("tier", ""),
        "geo_country_code": geo.get("country_code", "") or reputation.get("country_code", "") or "",
        "geo_asn": geo.get("asn", 0),
        "geo_org": geo.get("org", ""),
        "shodan_vulns": infra.get("vulns", []) or [],
    }

    # Recidivism
    super_session["previously_seen"] = any(s.get("previously_seen") for s in sessions)
    super_session["previous_sessions"] = max(
        (_coerce_int(s.get("previous_sessions")) for s in sessions), default=0
    )

    # WHAT — aggregate volume/behavior
    super_session["login_attempts"] = sum(_coerce_int(s.get("login_attempts")) for s in sessions)
    super_session["attack_velocity"] = max(
        (_coerce_float(s.get("attack_velocity")) for s in sessions), default=0.0
    )
    super_session["success_count"] = sum(_coerce_int(s.get("success_count")) for s in sessions)
    super_session["command_count"] = sum(_coerce_int(s.get("command_count")) for s in sessions)
    super_session["exfil_bytes"] = sum(_coerce_int(s.get("exfil_bytes")) for s in sessions)
    super_session["file_download_count"] = sum(
        _coerce_int(s.get("file_download_count")) for s in sessions
    )

    # Per-session quality tags aggregated (commands not aggregated; quality is per-session).
    all_quality_tags = []
    for s in sessions:
        all_quality_tags.extend(list(s.get("command_quality_tags") or []))
    super_session["command_quality_tags"] = sorted(set(all_quality_tags))
    super_session["commands"] = []

    # Honeypot diversity
    hp_types = [s.get("honeypot_type", "") for s in sessions if s.get("honeypot_type")]
    distinct_hp = sorted(set(hp_types))
    super_session["honeypot_type"] = (
        "multi" if len(distinct_hp) > 1 else (distinct_hp[0] if distinct_hp else "")
    )
    super_session["honeypot_types_hit"] = distinct_hp

    # SMB / lateral
    super_session["smb_share_enum"] = any(bool(s.get("smb_share_enum")) for s in sessions)
    super_session["epmapper_prescan"] = max(
        (_coerce_int(s.get("epmapper_prescan")) for s in sessions), default=0
    )
    cves = []
    for s in sessions:
        cves.extend(list(s.get("exploit_cve") or []))
    super_session["exploit_cve"] = sorted(set(cves))

    # Destination port — use the most common critical port if any session hit one
    dest_ports = [_coerce_int(s.get("destination_port")) for s in sessions]
    crit_hits = [p for p in dest_ports if p in _CRITICAL_PORTS]
    super_session["destination_port"] = (
        crit_hits[0] if crit_hits else (dest_ports[0] if dest_ports else 0)
    )

    # HOW — malware aggregation
    yara_all = []
    for s in sessions:
        yara_all.extend(list(s.get("yara_matches") or []))
    super_session["yara_matches"] = yara_all
    super_session["vt_malicious"] = max(
        (_coerce_int(s.get("vt_malicious")) for s in sessions), default=0
    )
    vt_fam = ""
    for s in sessions:
        f = str(s.get("vt_family") or "")
        if f:
            vt_fam = f
            break
    super_session["vt_family"] = vt_fam

    # HOW — MITRE aggregation
    tech_union = []
    for s in sessions:
        for t in s.get("mitre_techniques") or []:
            tech_union.append(t)
    super_session["mitre_techniques"] = tech_union
    # Pick kill_chain_phase from the session with the highest stage
    best_stage = -1
    best_phase = ""
    for s in sessions:
        st = _coerce_int(s.get("kill_chain_stage"))
        if st > best_stage:
            best_stage = st
            best_phase = str(s.get("kill_chain_phase") or "")
    super_session["kill_chain_stage"] = max(best_stage, 0)
    super_session["kill_chain_phase"] = best_phase

    result = score_session(super_session)
    result.scorer_mode = "ip_aggregate"
    result.sessions_aggregated = len(sessions)
    return result
