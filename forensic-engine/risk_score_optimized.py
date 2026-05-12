"""
ForenHive Risk Scoring — consolidated module.

Two scorers in one file:

  1. calculate_risk_score(session_data)  — per-session forensic scorer (18 signals,
       used by engine.py Phase 3 before sessions are stored in PostgreSQL).

  2. RiskScorer  — unified per-IP scorer (6 signals, reads from forensic_sessions
       after they are stored, used by engine.py Phase 9 and the backend API).
"""

import ipaddress
import json
import logging
import math
from datetime import datetime
from typing import Dict, List, Optional

import psycopg2
import psycopg2.extras
from elasticsearch import Elasticsearch

import config

log = logging.getLogger("risk_score_optimized")


class RiskScorer:
    """
    Unified risk scorer. One score per source_ip.
    Aggregates Cowrie + Dionaea + Galah data within a configurable time window.
    Reads from forensic_sessions (written by the engine) and ip_enrichment_cache.
    """

    def __init__(self):
        self.es = Elasticsearch(
            f"http://{config.ES_HOST}:{config.ES_PORT}",
            request_timeout=30,
        )
        # Store DSN — do NOT hold an open connection
        self._pg_dsn = dict(
            host=config.PG_HOST,
            database=config.PG_DB,
            user=config.PG_USER,
            password=config.PG_PASSWORD,
        )

    # ── connection helper ───────────────────────────────────────
    def _pg_connect(self):
        """Return a new psycopg2 connection (use as context manager)."""
        return psycopg2.connect(**self._pg_dsn)

    # ── public entry point ──────────────────────────────────────
    def calculate_risk_score(
        self,
        source_ip: str,
        time_window_hours: int = 24,
    ) -> Dict:
        """
        Calculate unified risk score for an IP across all honeypots.

        Returns dict with: source_ip, risk_score (0-100), risk_level,
        confidence, signal_breakdown, honeypots_hit, key_findings,
        recommendations, enrichment_snapshot.
        """
        log.info(f"Calculating risk score for {source_ip} (window={time_window_hours}h)")

        try:
            all_sessions = self._query_sessions_by_ip(source_ip, time_window_hours)

            if not all_sessions:
                log.warning(f"No sessions found for {source_ip}")
                return self._empty_score(source_ip)

            log.info(f"Found {len(all_sessions)} session(s) for {source_ip}")

            enrichment = self._query_enrichment(source_ip)

            sig1 = self._signal_reputation(source_ip, enrichment)
            sig2 = self._signal_compromise(all_sessions)
            sig3 = self._signal_brute_force(all_sessions)
            sig4 = self._signal_malware(all_sessions)
            sig5 = self._signal_anonymization(enrichment, all_sessions)
            sig6 = self._signal_sophistication(all_sessions)

            raw_signals = dict(
                reputation=sig1,
                compromise=sig2,
                brute_force=sig3,
                malware=sig4,
                anonymization=sig5,
                sophistication=sig6,
            )

            risk_score = min(100, sum(raw_signals.values()))
            risk_level = self._risk_level(risk_score)

            active_signals = sum(1 for v in raw_signals.values() if v > 0)
            confidence = self._confidence(active_signals)

            honeypots_hit = sorted(set(
                s["honeypot_type"] for s in all_sessions if s.get("honeypot_type")
            ))
            honeypot_summary = {
                "cowrie":  sum(1 for s in all_sessions if s.get("honeypot_type") == "cowrie"),
                "dionaea": sum(1 for s in all_sessions if s.get("honeypot_type") == "dionaea"),
                "galah":   sum(1 for s in all_sessions if s.get("honeypot_type") == "galah"),
                "zeek":    0,
            }

            signal_breakdown = {
                "reputation": {
                    "points": sig1,
                    "max":    25,
                    "label":  "IP Reputation",
                    "detail": self._detail_reputation(enrichment),
                },
                "compromise": {
                    "points": sig2,
                    "max":    25,
                    "label":  "Compromise Confirmed",
                    "detail": self._detail_compromise(all_sessions),
                },
                "brute_force": {
                    "points": sig3,
                    "max":    20,
                    "label":  "Brute Force / Automation",
                    "detail": self._detail_brute_force(all_sessions),
                },
                "malware": {
                    "points": sig4,
                    "max":    15,
                    "label":  "Malware Detected",
                    "detail": self._detail_malware(all_sessions),
                },
                "anonymization": {
                    "points": sig5,
                    "max":    10,
                    "label":  "Anonymization / Evasion",
                    "detail": self._detail_anonymization(enrichment),
                },
                "sophistication": {
                    "points": sig6,
                    "max":    5,
                    "label":  "Attack Sophistication",
                    "detail": self._detail_sophistication(all_sessions, honeypots_hit),
                },
            }

            key_findings    = self._build_key_findings(raw_signals, enrichment)
            recommendations = self._build_recommendations(risk_score, all_sessions)

            return {
                "source_ip":      source_ip,
                "risk_score":     risk_score,
                "risk_level":     risk_level,
                "confidence":     confidence,
                "active_signals": active_signals,
                "timestamp":      datetime.utcnow().isoformat() + "Z",

                "signal_breakdown":  signal_breakdown,
                "honeypots_hit":     honeypots_hit,
                "honeypot_count":    len(honeypots_hit),
                "honeypot_summary":  honeypot_summary,
                "sessions_count":    len(all_sessions),

                "key_findings":    key_findings,
                "recommendations": recommendations,

                "enrichment_snapshot": {
                    "country":    enrichment.get("geo", {}).get("country"),
                    "city":       enrichment.get("geo", {}).get("city"),
                    "asn":        enrichment.get("geo", {}).get("asn"),
                    "org":        enrichment.get("geo", {}).get("org"),
                    "is_tor":     enrichment.get("privacy", {}).get("is_tor", False),
                    "is_vpn":     enrichment.get("privacy", {}).get("is_vpn", False),
                    "is_hosting": enrichment.get("privacy", {}).get("is_hosting", False),
                    "abuse_score": enrichment.get("reputation", {}).get("abuse_score", 0),
                },
            }

        except Exception as e:
            log.error(f"Risk score calculation failed for {source_ip}: {e}", exc_info=True)
            raise

    # ════════════════════════════════════════════════════════════
    #  SIGNAL 1 — IP REPUTATION  (0-25)
    # ════════════════════════════════════════════════════════════
    def _signal_reputation(self, source_ip: str, enrichment: dict) -> int:
        if self._is_private(source_ip):
            return 0

        abuse = enrichment.get("reputation", {}).get("abuse_score", 0)
        if abuse >= 90:
            return 25
        elif abuse >= 70:
            return 18
        elif abuse >= 50:
            return 12
        elif abuse >= 30:
            return 6
        return 0

    # ════════════════════════════════════════════════════════════
    #  SIGNAL 2 — COMPROMISE CONFIRMED  (0-25)
    # ════════════════════════════════════════════════════════════
    def _signal_compromise(self, sessions: list) -> int:
        for s in sessions:
            if s.get("success_count", 0) > 0:
                return 25
        return 0

    # ════════════════════════════════════════════════════════════
    #  SIGNAL 3 — BRUTE FORCE / AUTOMATION  (0-20)
    # ════════════════════════════════════════════════════════════
    def _signal_brute_force(self, sessions: list) -> int:
        total_attempts = sum(s.get("login_attempts", 0) for s in sessions)
        max_velocity   = max((s.get("attack_velocity", 0.0) for s in sessions), default=0.0)

        if max_velocity > 50:
            base = 20
        elif total_attempts >= 500:
            base = 15
        elif total_attempts >= 200:
            base = 10
        elif total_attempts >= 50:
            base = 5
        else:
            base = 0

        has_targeted = any(
            "targeted_wordlist" in (s.get("enrichment_data") or {}).get("attack_types", [])
            for s in sessions
        )
        if has_targeted and base > 0:
            base = min(20, base + 2)

        return base

    # ════════════════════════════════════════════════════════════
    #  SIGNAL 4 — MALWARE DETECTED  (0-15)
    # ════════════════════════════════════════════════════════════
    def _signal_malware(self, sessions: list) -> int:
        best = 0
        for s in sessions:
            enrich = s.get("enrichment_data") or {}
            yara   = enrich.get("yara_matches", [])
            vt     = enrich.get("vt_malicious", 0)

            _HIGH_SEV  = {"Mirai_Botnet", "WannaCry_Ransomware", "Emotet_Loader",
                          "Cobalt_Strike", "Metasploit_Payload"}
            def _yara_name(m):
                return m if isinstance(m, str) else (m.get("family") or m.get("rule", ""))
            def _yara_sev(m):
                if isinstance(m, dict):
                    return m.get("severity", "").upper()
                return "CRITICAL" if _yara_name(m) in _HIGH_SEV else "MEDIUM"

            if any(_yara_sev(m) == "CRITICAL" for m in yara):
                return 15
            if any(_yara_sev(m) == "HIGH" for m in yara):
                best = max(best, 10)
            elif yara:
                best = max(best, 5)

            if vt >= 30:
                best = max(best, 10)
            elif vt >= 10:
                best = max(best, 5)

        return best

    # ════════════════════════════════════════════════════════════
    #  SIGNAL 5 — ANONYMIZATION / EVASION  (0-10)
    # ════════════════════════════════════════════════════════════
    def _signal_anonymization(self, enrichment: dict, sessions: list) -> int:
        """
        Score Tor/VPN usage + critical port targeting.
        Critical port bonus is CONDITIONAL — only if session data
        confirms targeting of high-value services.
        """
        privacy = enrichment.get("privacy", {}) or {}
        threat  = enrichment.get("threat_summary", {}) or {}
        pts = 0

        is_tor   = threat.get("is_tor", False) or privacy.get("is_tor", False)
        is_vpn   = threat.get("is_vpn", False) or privacy.get("is_vpn", False)
        is_proxy = threat.get("is_proxy", False) or privacy.get("is_proxy", False)

        if is_tor:
            pts += 7
        elif is_vpn or is_proxy:
            pts += 4

        # Critical port targeting — inferred from session honeypot type
        critical_ports = {22, 23, 445, 1433, 3306, 3389, 5432, 27017}
        ports_targeted = set()
        for s in sessions:
            hp = s.get("honeypot_type", "")
            if hp == "cowrie":
                ports_targeted.update({22, 23})
            elif hp == "dionaea":
                ports_targeted.update({445, 3306, 27017})
            elif s.get("destination_port"):
                ports_targeted.add(int(s["destination_port"]))

        # Critical port bonus only meaningful when combined with anonymization
        if (is_tor or is_vpn or is_proxy) and (ports_targeted & critical_ports):
            pts += 3

        return min(10, pts)

    # ════════════════════════════════════════════════════════════
    #  SIGNAL 6 — ATTACK SOPHISTICATION  (0-5)
    # ════════════════════════════════════════════════════════════
    def _signal_sophistication(self, sessions: list) -> int:
        # Use pre-computed kill_chain_stage stored in forensic_sessions
        max_kc = max(
            (int(s.get("kill_chain_stage") or 0) for s in sessions),
            default=0,
        )

        if max_kc >= 6:
            pts = 5
        elif max_kc >= 4:
            pts = 3
        elif max_kc >= 2:
            pts = 1
        else:
            pts = 0

        types = set(s.get("honeypot_type") for s in sessions if s.get("honeypot_type"))
        if len(types) > 1:
            pts = min(5, pts + 2)

        return pts

    # ════════════════════════════════════════════════════════════
    #  DATABASE HELPERS
    # ════════════════════════════════════════════════════════════

    def _query_sessions_by_ip(self, ip: str, hours: int) -> list:
        """Query all scored sessions for this IP within the time window."""
        with self._pg_connect() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT *
                    FROM forensic_sessions
                    WHERE source_ip = %s
                      AND started_at > NOW() - make_interval(hours => %s)
                      AND honeypot_type != 'unified'
                    ORDER BY started_at DESC
                    """,
                    (ip, hours),
                )
                return [dict(r) for r in cur.fetchall()]

    def _query_enrichment(self, ip: str) -> dict:
        """Query cached enrichment data for this IP."""
        with self._pg_connect() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT data FROM ip_enrichment_cache WHERE ip = %s LIMIT 1",
                    (ip,),
                )
                row = cur.fetchone()
                if not row:
                    return {}
                data = row["data"]
                return data if isinstance(data, dict) else json.loads(data)

    # ════════════════════════════════════════════════════════════
    #  STATIC UTILITIES
    # ════════════════════════════════════════════════════════════

    @staticmethod
    def _is_private(ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    @staticmethod
    def _risk_level(score: int) -> str:
        if score >= 80:
            return "CRITICAL"
        if score >= 60:
            return "HIGH"
        if score >= 40:
            return "MEDIUM"
        if score >= 20:
            return "LOW"
        return "INFO"

    @staticmethod
    def _confidence(active: int) -> str:
        if active >= 4:
            return "HIGH"
        if active >= 2:
            return "MEDIUM"
        return "LOW"

    # ════════════════════════════════════════════════════════════
    #  DETAIL GENERATORS (for signal_breakdown)
    # ════════════════════════════════════════════════════════════

    def _detail_reputation(self, enrichment: dict) -> str:
        rep = enrichment.get("reputation", {})
        abuse = rep.get("abuse_score", 0)
        reports = rep.get("total_reports", 0)
        return f"AbuseIPDB {abuse}/100 ({reports} reports)"

    def _detail_compromise(self, sessions: list) -> str:
        for s in sessions:
            if s.get("success_count", 0) > 0:
                hp = s.get("honeypot_type", "unknown")
                return f"Successful login on {hp}"
        return "No compromise"

    def _detail_brute_force(self, sessions: list) -> str:
        total = sum(s.get("login_attempts", 0) for s in sessions)
        hp_count = len(set(
            s["honeypot_type"] for s in sessions
            if s.get("login_attempts", 0) > 0 and s.get("honeypot_type")
        ))
        return f"{total} attempts across {hp_count} honeypot(s)"

    def _detail_malware(self, sessions: list) -> str:
        families = []
        for s in sessions:
            enrich = s.get("enrichment_data") or {}
            for m in enrich.get("yara_matches", []):
                family = m if isinstance(m, str) else (m.get("family") or m.get("rule", "unknown"))
                if family not in families:
                    families.append(family)
        if families:
            return f"Detected: {', '.join(families[:3])}"
        for s in sessions:
            enrich = s.get("enrichment_data") or {}
            vt = enrich.get("vt_malicious", 0)
            if vt > 0:
                return f"VirusTotal {vt} detections (no YARA hit)"
        return "No malware detected"

    def _detail_anonymization(self, enrichment: dict) -> str:
        p = enrichment.get("privacy", {}) or {}
        t = enrichment.get("threat_summary", {}) or {}
        if t.get("is_tor") or p.get("is_tor"):
            return "Tor exit node"
        if t.get("is_vpn") or p.get("is_vpn"):
            return "VPN detected"
        if t.get("is_proxy") or p.get("is_proxy"):
            return "Proxy detected"
        return "Direct connection"

    def _detail_sophistication(self, sessions: list, honeypots_hit: list) -> str:
        max_kc = max((int(s.get("kill_chain_stage") or 0) for s in sessions), default=0)
        phases = [
            "None", "Reconnaissance", "Weaponization", "Exploitation",
            "Installation", "C2", "Actions", "Lateral Movement", "Exfiltration",
        ]
        phase = phases[max_kc] if max_kc < len(phases) else f"Stage {max_kc}"
        multi = (
            f" | Multi-honeypot: {', '.join(honeypots_hit)}"
            if len(honeypots_hit) > 1 else ""
        )
        return f"Kill chain: {phase} (stage {max_kc}/8){multi}"

    # ════════════════════════════════════════════════════════════
    #  FINDINGS & RECOMMENDATIONS
    # ════════════════════════════════════════════════════════════

    def _build_key_findings(self, signals: dict, enrichment: dict) -> list:
        findings = []
        if signals["reputation"] >= 18:
            abuse = enrichment.get("reputation", {}).get("abuse_score", 0)
            findings.append(f"IP flagged as malicious (AbuseIPDB {abuse}%)")
        if signals["compromise"] > 0:
            findings.append("Confirmed system compromise (successful authentication)")
        if signals["brute_force"] > 0:
            findings.append("Automated brute-force attack detected")
        if signals["malware"] > 0:
            findings.append("Malware or botnet payload detected")
        if signals["anonymization"] >= 7:
            findings.append("Tor exit node used for anonymization")
        elif signals["anonymization"] >= 4:
            findings.append("VPN/proxy used for evasion")
        if signals["sophistication"] >= 3:
            findings.append("Multi-stage attack with advanced kill chain progression")
        return findings

    def _build_recommendations(self, score: int, sessions: list) -> list:
        recs = []
        if score >= 80:
            recs.append({
                "priority": "IMMEDIATE",
                "action": "Block source IP at perimeter firewall",
                "rationale": f"Risk score {score}/100 — confirmed high-severity threat",
            })
            recs.append({
                "priority": "IMMEDIATE",
                "action": "Force password reset on any compromised accounts",
                "rationale": "Successful authentication detected on honeypot",
            })
        elif score >= 60:
            recs.append({
                "priority": "HIGH",
                "action": "Block source IP at firewall",
                "rationale": f"Risk score {score}/100 — elevated threat",
            })
            recs.append({
                "priority": "HIGH",
                "action": "Review access logs for unauthorized activity from this IP/ASN",
                "rationale": "Attacker may have probed production systems",
            })
        elif score >= 40:
            recs.append({
                "priority": "MEDIUM",
                "action": "Add IP to watchlist and monitor for repeat activity",
                "rationale": f"Risk score {score}/100 — moderate threat",
            })

        if any(
            (s.get("enrichment_data") or {}).get("yara_matches")
            or (s.get("enrichment_data") or {}).get("vt_malicious", 0) > 0
            for s in sessions
        ):
            recs.append({
                "priority": "HIGH",
                "action": "Quarantine and analyze malware samples; export SHA-256 hashes to TIP",
                "rationale": "Malware detected — lateral spread risk",
            })

        recs.append({
            "priority": "MEDIUM",
            "action": "Export IOCs in STIX 2.1 format to SIEM for correlation",
            "rationale": "Enable cross-environment detection",
        })

        return recs

    def _empty_score(self, ip: str) -> dict:
        return {
            "source_ip":        ip,
            "risk_score":       0,
            "risk_level":       "INFO",
            "confidence":       "LOW",
            "active_signals":   0,
            "timestamp":        datetime.utcnow().isoformat() + "Z",
            "signal_breakdown": {},
            "honeypots_hit":    [],
            "honeypot_count":   0,
            "honeypot_summary": {"cowrie": 0, "dionaea": 0, "galah": 0, "zeek": 0},
            "sessions_count":   0,
            "key_findings":     [],
            "recommendations":  [],
            "enrichment_snapshot": {},
        }


# ══════════════════════════════════════════════════════════════════════════════
#  PER-SESSION FORENSIC SCORER  (18 signals — called by engine.py Phase 3)
# ══════════════════════════════════════════════════════════════════════════════

# ── Critical ports ────────────────────────────────────────────────────────────
_CRITICAL_PORTS = {
    22: "SSH", 23: "Telnet", 445: "SMB", 1433: "MSSQL", 3306: "MySQL",
    5432: "PostgreSQL", 6379: "Redis", 9200: "Elasticsearch",
    27017: "MongoDB", 2375: "Docker daemon", 2222: "SSH (alternate)",
}

# ── Signal weights ────────────────────────────────────────────────────────────
_SMB_SHARE_ENUM      = 30
_EPMAPPER_PRESCAN    = 15
_EXPLOIT_CVE         = 40
_MULTI_HONEYPOT      = 10
_SUCCESS_COMPROMISE  = 25
_ATTACKER_VULN       = 10
_HOSTING             = 5
_VELOCITY            = 5
_RECIDIVISM          = 10
_TEMPORAL            = 5
_LOGIN_HIGH = 200
_LOGIN_MED  = 50
_LOGIN_LOW  = 10
_VELOCITY_THRESHOLD  = 2.0

_SESSION_HIGH_SEV_YARA = {"Mirai_Botnet", "WannaCry_Ransomware", "Emotet_Loader",
                          "Cobalt_Strike", "Metasploit_Payload"}

_VPS_ASN_PATTERNS = (
    "AMAZON", "AWS", "DIGITALOCEAN", "LINODE", "OVH", "HETZNER",
    "CHOOPA", "VULTR", "LEASEWEB", "CONTABO", "MICROSOFT", "AZURE",
    "GOOGLE", "CLOUDFLARE", "ALIBABA", "TENCENT", "SCALEWAY", "UPCLOUD",
    "ONLINE SAS", "SERVER4YOU", "M247",
)
_SHODAN_BAD_TAGS = {"malware", "c2", "botnet", "tor", "cloud"}

_MITRE_MAP = {
    "brute_force":      {"id": "T1110",     "name": "Brute Force",                           "tactic": "credential-access"},
    "pass_guessing":    {"id": "T1110.001", "name": "Password Guessing",                     "tactic": "credential-access"},
    "valid_accounts":   {"id": "T1078",     "name": "Valid Accounts",                        "tactic": "initial-access"},
    "net_share_disc":   {"id": "T1135",     "name": "Network Share Discovery",               "tactic": "discovery"},
    "net_service_scan": {"id": "T1046",     "name": "Network Service Scanning",              "tactic": "discovery"},
    "active_scan":      {"id": "T1595",     "name": "Active Scanning",                       "tactic": "reconnaissance"},
    "exploit_app":      {"id": "T1190",     "name": "Exploit Public-Facing Application",     "tactic": "initial-access"},
    "ingress_tool":     {"id": "T1105",     "name": "Ingress Tool Transfer",                 "tactic": "command-and-control"},
    "cmd_scripting":    {"id": "T1059",     "name": "Command and Scripting Interpreter",     "tactic": "execution"},
    "exfiltration_c2":  {"id": "T1041",     "name": "Exfiltration Over C2 Channel",         "tactic": "exfiltration"},
    "proxy_anon":       {"id": "T1090",     "name": "Proxy",                                 "tactic": "command-and-control"},
    "lateral_smb":      {"id": "T1021.002", "name": "Remote Services: SMB/Windows Admin Shares", "tactic": "lateral-movement"},
    "obfuscated_files": {"id": "T1027",     "name": "Obfuscated Files or Information",       "tactic": "defense-evasion"},
    "compromise_infra": {"id": "T1584",     "name": "Compromise Infrastructure",             "tactic": "resource-development"},
    "acquire_infra":    {"id": "T1583",     "name": "Acquire Infrastructure",                "tactic": "resource-development"},
}


def _hosting_asn(geo_org: str, geo_isp: str) -> bool:
    haystack = f"{geo_org} {geo_isp}".upper()
    return any(p in haystack for p in _VPS_ASN_PATTERNS)


def risk_level(score: int) -> str:
    """Human-readable risk level from numeric score (0-100)."""
    if score >= 80: return "CRITICAL"
    if score >= 60: return "HIGH"
    if score >= 40: return "MEDIUM"
    if score >= 20: return "LOW"
    return "INFO"


def calculate_risk_score(session_data: dict) -> dict:
    """Per-session forensic risk assessment (18 signals). Returns score 0-100."""

    source_ip     = session_data.get("source_ip", "unknown")
    session_id    = session_data.get("session_id", "")
    is_private    = session_data.get("is_private", False)
    vt_available  = session_data.get("vt_available", True)
    network_class = session_data.get("network_class", "external")

    abuse_score    = int(session_data.get("abuse_score", 0))
    abuse_reports  = int(session_data.get("abuse_total_reports", 0))
    abuse_distinct = int(session_data.get("abuse_distinct_users", 0))
    abuse_last     = session_data.get("abuse_last_reported", "")
    abuse_cats     = list(session_data.get("abuse_categories", []) or [])
    abuse_usage    = session_data.get("abuse_usage_type", "")
    is_tor         = session_data.get("is_tor", False)
    is_vpn         = session_data.get("is_vpn", False)
    is_proxy       = session_data.get("is_proxy", False)
    is_hosting     = session_data.get("is_hosting", False)
    is_datacenter  = session_data.get("is_datacenter", False)
    is_abuser_list = session_data.get("is_abuser_listed", False)
    is_bogon       = session_data.get("is_bogon", False)

    geo_country      = session_data.get("geo_country", "")
    geo_country_code = session_data.get("geo_country_code", "")
    geo_region       = session_data.get("geo_region", "")
    geo_city         = session_data.get("geo_city", "")
    geo_asn          = session_data.get("geo_asn", 0)
    geo_org          = session_data.get("geo_org", "")
    geo_isp          = session_data.get("geo_isp", "")
    network_cidr     = session_data.get("network_cidr", "")
    ptr_hostname     = session_data.get("ptr_hostname", "")
    all_hostnames    = list(session_data.get("all_hostnames", []) or [])
    abuse_contact    = session_data.get("abuse_contact", "")
    threat_tier      = session_data.get("threat_tier", "")

    shodan_vulns     = list(session_data.get("shodan_vulns", []) or [])
    shodan_tags      = list(session_data.get("shodan_tags", []) or [])
    shodan_ports     = list(session_data.get("shodan_open_ports", []) or [])
    shodan_hostnames = list(session_data.get("shodan_hostnames", []) or [])

    yara_matches  = list(session_data.get("yara_matches") or [])
    vt_malicious  = int(session_data.get("vt_malicious", 0))
    vt_family     = session_data.get("vt_family", "") or ""
    vt_tags       = list(session_data.get("vt_tags", []) or [])
    vt_names      = list(session_data.get("vt_names", []) or [])
    vt_first_seen = session_data.get("vt_first_seen", "") or ""
    sha256_hashes = list(session_data.get("sha256_hashes", []) or [])

    attempts      = int(session_data.get("login_attempts", 0))
    success_count = int(session_data.get("success_count", 0))
    dest_port     = session_data.get("destination_port")
    command_count = int(session_data.get("command_count", 0))
    exfil_bytes   = int(session_data.get("exfil_bytes", 0))

    smb_share_enum = bool(session_data.get("smb_share_enum", False))
    epmapper_count = int(session_data.get("epmapper_prescan", 0) or 0)
    exploit_cve    = list(session_data.get("exploit_cve") or [])

    honeypot_types    = sorted(set(session_data.get("honeypot_types_hit") or []))
    duration_sec      = float(session_data.get("session_duration_sec", 0) or 0)
    velocity          = float(session_data.get("attack_velocity", 0) or 0)
    is_off_hours      = bool(session_data.get("is_off_hours", False))
    hour_local        = int(session_data.get("hour_local", -1))
    previously_seen   = bool(session_data.get("previously_seen", False))
    previous_sessions = int(session_data.get("previous_sessions", 0))

    w = 2 if is_private else 1

    score = 0; notes = []; breakdown = {}; techniques = []; attack_types = set()

    # 1. Reputation (0-40)
    if not is_private:
        rep_pts = int(abuse_score * 0.40); score += rep_pts
        breakdown["reputation"] = {"points": rep_pts, "max": 40,
            "detail": f"AbuseIPDB confidence {abuse_score}/100 → {rep_pts} pts",
            "available": abuse_score > 0}
    else:
        breakdown["reputation"] = {"points": 0, "max": 40,
            "detail": f"private IP ({network_class}) — AbuseIPDB not applicable",
            "available": False}
        notes.append(f"private_ip:{network_class} — reputation skipped, behavioral weight ×2")

    # 2. Reputation volume (0-10)
    vol_pts = 0
    if not is_private and abuse_reports > 0:
        vol_pts = min(int(math.log10(max(abuse_reports, 1)) * 3.3), 10); score += vol_pts
    breakdown["reputation_volume"] = {"points": vol_pts, "max": 10,
        "detail": f"AbuseIPDB reported {abuse_reports} time(s)" if not is_private
                  else "private IP — not applicable",
        "available": (not is_private) and abuse_reports > 0}

    # 3. Anonymization (0-10)
    anon_pts = 0; anon_flags = []
    if not is_private:
        if is_tor:   anon_pts = 10; anon_flags.append("Tor")
        elif is_vpn: anon_pts = 10; anon_flags.append("VPN")
        elif is_proxy: anon_pts = 10; anon_flags.append("proxy")
        score += anon_pts
        if anon_pts: techniques.append("proxy_anon"); attack_types.add("anonymized_attacker")
        if is_bogon: notes.append("bogon_ip:source IP is in unallocated/reserved space (spoofed?)")
        if is_abuser_list: notes.append("iplocate_abuser_listed:IP flagged as abuser by IPLocate")
    breakdown["anonymization"] = {"points": anon_pts, "max": 10,
        "detail": f"anonymization: {', '.join(anon_flags)}" if anon_flags
                  else ("no anonymization detected" if not is_private else "private IP — not applicable"),
        "available": not is_private}

    # 4. Attacker infrastructure / Shodan (0-15)
    infra_pts = 0; infra_details = []; attacker_compromised = False; attacker_is_hosting = False
    if shodan_vulns:
        infra_pts += _ATTACKER_VULN; attacker_compromised = True
        infra_details.append(f"{len(shodan_vulns)} known vulns on attacker IP (likely compromised zombie)")
        techniques.append("compromise_infra"); attack_types.add("compromised_host")
    bad_tags = [t for t in shodan_tags if t.lower() in _SHODAN_BAD_TAGS]
    if bad_tags: infra_details.append(f"Shodan tags: {bad_tags}")
    if is_hosting or is_datacenter or _hosting_asn(geo_org, geo_isp):
        infra_pts += _HOSTING; attacker_is_hosting = True
        src = geo_org or geo_isp or "VPS"
        infra_details.append(f"datacenter/hosting ({src})" if is_datacenter else f"hosted infrastructure ({src})")
        techniques.append("acquire_infra")
    _cat_map = {"Brute-Force": "brute_force", "SSH": "brute_force", "FTP Brute-Force": "brute_force",
                "Port Scan": "reconnaissance", "Web App Attack": "exploitation",
                "SQL Injection": "exploitation", "Hacking": "exploitation", "DDoS Attack": "ddos",
                "Phishing": "phishing", "Web Spam": "spam", "Email Spam": "spam",
                "Bad Web Bot": "automated", "Exploited Host": "compromised_host"}
    for label in abuse_cats:
        t = _cat_map.get(label)
        if t: attack_types.add(t)
    if infra_pts > 0: score += infra_pts
    breakdown["attacker_infrastructure"] = {"points": infra_pts, "max": 15,
        "detail": "; ".join(infra_details) if infra_details else "no attacker-infrastructure red flags",
        "available": not is_private}

    # 5. YARA (0-45)
    yara_pts = 0
    if yara_matches:
        high_sev = [m for m in yara_matches if m in _SESSION_HIGH_SEV_YARA]
        yara_pts = (20 if high_sev else 12) * w
        if not vt_available: yara_pts += 5; notes.append("vt_unavailable:yara_score_includes_uncertainty_bonus")
        score += yara_pts; techniques.append("ingress_tool")
        if high_sev: techniques.append("obfuscated_files")
        attack_types.add("malware_delivery")
        detail = f"YARA rules matched: {', '.join(yara_matches)}" + (" (×2 weight, private IP)" if w == 2 else "")
    else:
        detail = "no YARA matches"
    breakdown["malware_yara"] = {"points": yara_pts, "max": 45, "detail": detail, "available": True}

    # 6. VirusTotal (0-15)
    vt_pts = 0
    if vt_available:
        if vt_malicious > 10:   vt_pts = 15; vt_detail = f"{vt_malicious} AV engines flagged"
        elif vt_malicious > 0:  vt_pts = 8;  vt_detail = f"{vt_malicious} AV engine(s) flagged"
        else:                   vt_detail = "clean or unknown on VirusTotal"
        score += vt_pts
        if vt_family: vt_detail += f" — family: {vt_family}"
        if vt_tags:   vt_detail += f" — tags: {vt_tags[:4]}"
        if vt_pts:    attack_types.add("malware_delivery")
    else:
        vt_detail = "VirusTotal quota exhausted — result unavailable"
        notes.append("vt_quota_exhausted:vt_signal_unavailable")
    breakdown["malware_vt"] = {"points": vt_pts, "max": 15, "detail": vt_detail, "available": vt_available}

    # 7. Login volume (0-20)
    login_pts = 0
    if attempts > _LOGIN_HIGH:
        login_pts = 10 * w; login_detail = f"{attempts} attempts (>{_LOGIN_HIGH} high-volume brute force)"
        techniques.append("pass_guessing")
    elif attempts > _LOGIN_MED:
        login_pts = 5 * w;  login_detail = f"{attempts} attempts (>{_LOGIN_MED} credential spray)"
        techniques.append("brute_force")
    elif attempts > _LOGIN_LOW:
        login_pts = 2 * w;  login_detail = f"{attempts} attempts (>{_LOGIN_LOW} low-volume probe)"
        techniques.append("brute_force")
    else:
        login_detail = f"{attempts} login attempt(s) — below threshold"
    if login_pts:
        score += login_pts; attack_types.add("brute_force")
        if w == 2: login_detail += " (×2 weight, private IP)"
    breakdown["login_volume"] = {"points": login_pts, "max": 20, "detail": login_detail, "available": True}

    # 8. Successful compromise (+25)
    compromise_pts = 0
    if success_count > 0:
        compromise_pts = _SUCCESS_COMPROMISE; score += compromise_pts
        techniques.append("valid_accounts"); attack_types.add("credential_compromise")
        notes.append(f"successful_login:{success_count} auth(s) — T1078 Valid Accounts")
    breakdown["successful_compromise"] = {"points": compromise_pts, "max": _SUCCESS_COMPROMISE,
        "detail": f"{success_count} successful login(s) out of {attempts} attempts"
                  if success_count else "no successful authentications", "available": True}

    # 9. Critical port (0-5)
    port_pts = 0; port_name = ""
    if dest_port:
        try: port_name = _CRITICAL_PORTS.get(int(dest_port), "")
        except (ValueError, TypeError): port_name = ""
        if port_name:
            port_pts = 5; score += port_pts; attack_types.add("critical_service_targeting")
            if int(dest_port) not in (22, 23): techniques.append("exploit_app")
    breakdown["critical_port"] = {"points": port_pts, "max": 5,
        "detail": f"port {dest_port} ({port_name})" if port_name
                  else (f"port {dest_port} (non-critical)" if dest_port else "no destination port"),
        "available": dest_port is not None}

    # 10. Commands (0-10)
    cmd_pts = 0
    if command_count > 20:
        cmd_pts = 5 * w; cmd_detail = f"{command_count} commands executed (active post-exploitation)"
        techniques.append("cmd_scripting"); attack_types.add("post_exploitation")
    elif command_count > 5:
        cmd_pts = 2 * w; cmd_detail = f"{command_count} commands executed (interactive session)"
        techniques.append("cmd_scripting"); attack_types.add("post_exploitation")
    else:
        cmd_detail = f"{command_count} command(s) — below threshold"
    if cmd_pts:
        score += cmd_pts
        if w == 2: cmd_detail += " (×2 weight, private IP)"
    breakdown["commands"] = {"points": cmd_pts, "max": 10, "detail": cmd_detail, "available": True}

    # 11. Exfiltration (0-10)
    exfil_pts = 0
    if exfil_bytes > 1_000_000:
        exfil_pts = 5 * w; exfil_detail = f"{exfil_bytes / 1_000_000:.1f} MB transferred (likely exfiltration)"
        techniques.append("exfiltration_c2"); attack_types.add("post_exploitation")
    elif exfil_bytes > 100_000:
        exfil_pts = 2 * w; exfil_detail = f"{exfil_bytes / 1_000:.0f} KB transferred (suspicious volume)"
        attack_types.add("post_exploitation")
    else:
        exfil_detail = f"{exfil_bytes} bytes transferred — normal range"
    if exfil_pts:
        score += exfil_pts
        if w == 2: exfil_detail += " (×2 weight, private IP)"
    breakdown["exfiltration"] = {"points": exfil_pts, "max": 10, "detail": exfil_detail, "available": True}

    # 12. Velocity (0-15)  — tiered: DoS/flood gets 15, fast scan 10, scripted 5
    vel_pts = 0
    if velocity >= 50 and attempts >= _LOGIN_LOW:
        vel_pts = 15; attack_types.add("dos_flood"); attack_types.add("automated")
        vel_detail = f"{velocity:.1f} attempts/sec over {duration_sec:.0f}s (DoS/flood — automated)"
    elif velocity >= 10 and attempts >= _LOGIN_LOW:
        vel_pts = 10; attack_types.add("automated")
        vel_detail = f"{velocity:.1f} attempts/sec over {duration_sec:.0f}s (high-speed scan)"
    elif velocity >= _VELOCITY_THRESHOLD and attempts >= _LOGIN_LOW:
        vel_pts = 5; attack_types.add("automated")
        vel_detail = f"{velocity:.1f} attempts/sec over {duration_sec:.0f}s (automated tooling)"
    else:
        vel_detail = f"{velocity:.2f} attempts/sec" if duration_sec > 0 else "insufficient data"
    if vel_pts:
        score += vel_pts
    breakdown["attack_velocity"] = {"points": vel_pts, "max": 15,
        "detail": vel_detail, "available": duration_sec > 0}

    # 13. SMB share enum (+30)
    smb_enum_pts = 0
    if smb_share_enum:
        smb_enum_pts = _SMB_SHARE_ENUM; score += smb_enum_pts
        techniques += ["net_share_disc", "lateral_smb"]
        attack_types.add("reconnaissance"); attack_types.add("lateral_movement")
        notes.append("smb:NetShareEnum (T1135) detected")
    breakdown["smb_share_enum"] = {"points": smb_enum_pts, "max": _SMB_SHARE_ENUM,
        "detail": "NetShareEnum (SRVSVC opnum 15) observed" if smb_enum_pts else "no SMB share enumeration",
        "available": True}

    # 14. SMB epmapper (+15)
    epm_pts = 0
    if epmapper_count > 0:
        epm_pts = _EPMAPPER_PRESCAN; score += epm_pts; techniques.append("net_service_scan")
        attack_types.add("reconnaissance"); notes.append(f"smb:epmapper_prescan ({epmapper_count} queries, T1046)")
    breakdown["smb_epmapper"] = {"points": epm_pts, "max": _EPMAPPER_PRESCAN,
        "detail": f"epmapper pre-scan ({epmapper_count} DCE/RPC queries)" if epm_pts else "no epmapper scanning",
        "available": True}

    # 15. Exploit CVE (+40)
    exp_pts = 0
    if exploit_cve:
        exp_pts = _EXPLOIT_CVE; score += exp_pts; techniques.append("exploit_app")
        attack_types.add("exploitation"); notes.append(f"exploit_probe:{exploit_cve} (T1190)")
    breakdown["exploit_cve"] = {"points": exp_pts, "max": _EXPLOIT_CVE,
        "detail": f"CVE probes: {', '.join(exploit_cve)}" if exp_pts else "no known exploit probes",
        "available": True}

    # 16. Multi-honeypot (+10)
    multi_pts = 0
    if len(honeypot_types) > 1:
        multi_pts = _MULTI_HONEYPOT; score += multi_pts; techniques.append("active_scan")
        attack_types.add("reconnaissance"); notes.append(f"multi_honeypot:{honeypot_types} (T1595)")
    breakdown["multi_honeypot"] = {"points": multi_pts, "max": _MULTI_HONEYPOT,
        "detail": f"hit {len(honeypot_types)} honeypot types: {honeypot_types}" if multi_pts
                  else f"single honeypot: {honeypot_types[0] if honeypot_types else 'unknown'}",
        "available": True}

    # 17. Recidivism (+10)
    recid_pts = 0
    if previously_seen:
        recid_pts = _RECIDIVISM; score += recid_pts; attack_types.add("persistent_attacker")
        notes.append(f"recidivism:{previous_sessions}_prior_sessions")
    breakdown["recidivism"] = {"points": recid_pts, "max": _RECIDIVISM,
        "detail": f"previously seen in {previous_sessions} prior session(s)" if previously_seen
                  else "first time seen on this platform", "available": True}

    # 18. Temporal anomaly (+5)
    temporal_pts = 0
    if is_off_hours:
        temporal_pts = _TEMPORAL; score += temporal_pts; attack_types.add("off_hours")
    breakdown["temporal_anomaly"] = {"points": temporal_pts, "max": _TEMPORAL,
        "detail": f"session started at {hour_local:02d}:00 local time (off-hours)" if temporal_pts
                  else (f"session started at {hour_local:02d}:00 local time"
                        if hour_local >= 0 else "no timestamp available"),
        "available": hour_local >= 0}

    # ── Finalize ──────────────────────────────────────────────────────────────
    score_uncapped = score
    final_score = min(score, 100)
    level = risk_level(final_score)
    lateral = bool(
        smb_share_enum or "lateral_movement" in attack_types
        or any(t in {"net_share_disc", "lateral_smb"} for t in techniques)
        or bool(exploit_cve)
    ) or (is_private and final_score >= 50)

    active_signals = sum(1 for v in breakdown.values() if v["points"] > 0)
    has_reputation = (not is_private) and abuse_score > 0

    if not vt_available and not yara_matches and not exploit_cve:
        confidence = "LOW"
    elif active_signals >= 4 and (vt_available or exploit_cve or yara_matches or success_count):
        confidence = "HIGH"
    elif active_signals >= 2 or exploit_cve or (yara_matches and vt_available) or success_count:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    seen_ids = set(); mitre_out = []
    for key in techniques:
        t = _MITRE_MAP.get(key)
        if t and t["id"] not in seen_ids:
            mitre_out.append(dict(t)); seen_ids.add(t["id"])

    dq_warnings = []
    if not vt_available: dq_warnings.append("VirusTotal quota exhausted — malware verdict may be incomplete")
    if is_private: dq_warnings.append(f"Private IP ({network_class}) — AbuseIPDB/GeoIP/IPLocate not applicable")
    if not is_private and not has_reputation: dq_warnings.append("AbuseIPDB returned no data — IP may be unlisted or key missing")
    if not honeypot_types: dq_warnings.append("No honeypot-type correlation data")
    if duration_sec == 0: dq_warnings.append("No session duration — velocity and off-hours checks unavailable")

    attacker_profile = _session_attacker_profile(is_private, network_class, is_tor, is_vpn,
                                                  is_proxy, attacker_is_hosting, attacker_compromised)
    attribution = {
        "source_ip": source_ip, "country": geo_country or "unknown",
        "country_code": geo_country_code or "", "region": geo_region, "city": geo_city,
        "asn": geo_asn, "asn_org": geo_org, "isp": geo_isp, "network_cidr": network_cidr,
        "ptr_hostname": ptr_hostname, "hostnames": sorted(set(shodan_hostnames + all_hostnames)),
        "abuse_contact": abuse_contact, "abuse_usage_type": abuse_usage,
        "abuse_categories": abuse_cats, "abuse_distinct_reporters": abuse_distinct,
        "abuse_last_reported": abuse_last, "is_hosting": attacker_is_hosting,
        "is_datacenter": is_datacenter, "is_bogon": is_bogon, "is_abuser_listed": is_abuser_list,
        "likely_compromised": attacker_compromised, "anonymization": anon_flags,
        "attacker_profile": attacker_profile, "threat_tier": threat_tier,
        "previously_seen": previously_seen, "previous_session_count": previous_sessions,
    }
    iocs = {
        "source_ip": source_ip, "session_id": session_id, "asn": geo_asn, "asn_org": geo_org,
        "country_code": geo_country_code, "city": geo_city, "network_cidr": network_cidr,
        "ptr_hostname": ptr_hostname, "sha256_hashes": sha256_hashes,
        "yara_families": yara_matches, "vt_families": [vt_family] if vt_family else [],
        "vt_tags": vt_tags, "vt_file_names": vt_names[:5], "cves_probed": exploit_cve,
        "ports_targeted": [dest_port] if dest_port else [],
        "hostnames": sorted(set(shodan_hostnames + all_hostnames)),
        "abuse_categories": abuse_cats, "abuse_contact": abuse_contact,
    }
    narrative = _session_narrative(
        source_ip, is_private, network_class, geo_country, geo_org, attribution,
        honeypot_types, attempts, success_count, dest_port, port_name,
        yara_matches, vt_malicious, vt_available, vt_family, vt_tags,
        exploit_cve, epmapper_count, smb_share_enum,
        command_count, exfil_bytes, velocity, duration_sec, is_off_hours,
        hour_local, previously_seen, previous_sessions, attacker_compromised,
        lateral, confidence, final_score, level,
    )
    actions = _session_recommendations(
        source_ip, final_score, level, lateral, set(attack_types),
        exploit_cve, yara_matches, vt_available, is_private,
        success_count, attacker_compromised,
    )

    return {
        "score": final_score, "score_uncapped": score_uncapped, "level": level,
        "confidence": confidence, "signal_breakdown": breakdown,
        "attack_types": sorted(attack_types), "mitre_techniques": mitre_out,
        "lateral_movement": lateral,
        "data_quality": {
            "vt_available": vt_available, "reputation_available": has_reputation,
            "smb_data_available": bool(smb_share_enum or epmapper_count),
            "multi_honeypot_data": bool(honeypot_types),
            "shodan_data": bool(shodan_vulns or shodan_tags or shodan_ports),
            "geo_data": bool(geo_country_code), "timing_data": duration_sec > 0,
            "warnings": dq_warnings,
        },
        "notes": notes, "narrative": narrative, "recommended_actions": actions,
        "iocs": iocs, "attribution": attribution,
    }


def _session_attacker_profile(is_private, network_class, is_tor, is_vpn, is_proxy,
                               is_hosting, is_compromised) -> str:
    if is_private: return f"internal_{network_class}"
    if is_tor: return "tor_exit_node"
    if is_compromised: return "compromised_host_botnet_zombie"
    if is_hosting: return "hosting_provider_vps"
    if is_vpn or is_proxy: return "commercial_anonymization"
    return "residential_or_unknown"


def _session_narrative(
    ip, is_private, network_class, country, org, attribution,
    honeypot_types, attempts, success_count, dest_port, port_name,
    yara_matches, vt_malicious, vt_available, vt_family, vt_tags,
    exploit_cve, epmapper_count, smb_share_enum,
    command_count, exfil_bytes, velocity, duration_sec, is_off_hours,
    hour_local, previously_seen, previous_sessions, attacker_compromised,
    lateral, confidence, score, level,
) -> str:
    parts = []
    if is_private:
        subject = f"Internal host {ip} ({network_class.replace('_', ' ')})"
    else:
        geo_frag = ""
        if country and country != "unknown":
            city = attribution.get("city") or ""
            geo_frag = f" (origin: {city + ', ' if city else ''}{country}"
            if org: geo_frag += f", {org}"
            cidr = attribution.get("network_cidr") or ""
            if cidr: geo_frag += f", CIDR {cidr}"
            geo_frag += ")"
        ptr = attribution.get("ptr_hostname") or ""
        if ptr: geo_frag += f" PTR={ptr}"
        profile = attribution.get("attacker_profile", "")
        profile_frag = f" [{profile.replace('_', ' ')}]" if profile and profile != "residential_or_unknown" else ""
        subject = f"External host {ip}{geo_frag}{profile_frag}"

    if len(honeypot_types) > 1:
        hp_str = f"across {len(honeypot_types)} honeypot types ({', '.join(honeypot_types)})"
    elif honeypot_types:
        hp_str = f"against the {honeypot_types[0]} honeypot"
    else:
        hp_str = "against the honeypot infrastructure"
    parts.append(f"{subject} was observed performing malicious activity {hp_str}.")

    cats = attribution.get("abuse_categories") or []
    distinct = attribution.get("abuse_distinct_reporters") or 0
    if cats or distinct:
        cat_str = f" — categories: {', '.join(cats[:5])}" if cats else ""
        rep_str = f" reported by {distinct} distinct reporters" if distinct else ""
        parts.append(f"AbuseIPDB shows prior malicious activity{rep_str}{cat_str}.")

    if previously_seen:
        parts.append(f"This IP is a known persistent attacker — previously seen in {previous_sessions} scored session(s).")

    if success_count > 0:
        svc = f" on port {dest_port} ({port_name})" if port_name else ""
        parts.append(f"CRITICAL: {success_count} SUCCESSFUL authentication(s){svc} out of {attempts} attempts — credentials were compromised (T1078).")
    elif attempts > _LOGIN_HIGH:
        svc = f" on port {dest_port} ({port_name})" if port_name else ""
        parts.append(f"It launched a high-volume brute-force attack with {attempts} login attempts{svc}.")
    elif attempts > _LOGIN_MED:
        parts.append(f"It performed a credential spray with {attempts} login attempts.")
    elif attempts > _LOGIN_LOW:
        parts.append(f"It probed authentication with {attempts} login attempts.")

    if velocity >= _VELOCITY_THRESHOLD and attempts >= _LOGIN_LOW:
        parts.append(f"Attack velocity was {velocity:.1f} attempts/second over {duration_sec:.0f} seconds, indicating automated tooling.")

    smb_parts = []
    if smb_share_enum: smb_parts.append("network share enumeration (NetShareEnum/T1135)")
    if epmapper_count > 0: smb_parts.append(f"DCE/RPC epmapper pre-scanning ({epmapper_count} queries/T1046)")
    if smb_parts: parts.append(f"SMB activity included {' and '.join(smb_parts)}.")

    if exploit_cve:
        parts.append(f"Known vulnerability probes were detected: {', '.join(exploit_cve)} (T1190).")

    if yara_matches:
        malware_desc = f"Dropped files matched YARA rules ({', '.join(yara_matches)})"
        if vt_family: malware_desc += f", identified as the {vt_family} family"
        if vt_tags: malware_desc += f" (VT tags: {', '.join(vt_tags[:3])})"
        if vt_available and vt_malicious > 0: malware_desc += f", flagged by {vt_malicious} AV engine(s)."
        elif not vt_available: malware_desc += ". VirusTotal confirmation is unavailable (quota exhausted)."
        else: malware_desc += " but appeared clean on VirusTotal."
        parts.append(malware_desc)

    if command_count > 5:
        parts.append(f"Interactive post-exploitation was observed with {command_count} commands executed.")
    if exfil_bytes > 100_000:
        parts.append(f"A data transfer of {exfil_bytes / 1_000_000:.2f} MB was recorded, suggesting exfiltration.")
    if attacker_compromised:
        parts.append("Shodan reports known CVEs on the attacker's own IP — this host is likely a compromised zombie participating in a botnet.")
    if is_off_hours and hour_local >= 0:
        parts.append(f"The session occurred during off-hours ({hour_local:02d}:00 defender local time).")
    if lateral:
        parts.append("Given the private IP origin and high behavioral score, lateral movement or insider threat activity is strongly suspected.")

    conf_phrase = {
        "HIGH": "Evidence is strong and corroborated by multiple independent signals.",
        "MEDIUM": "Evidence is moderate; some signals may be incomplete.",
        "LOW": "Evidence is limited; score may change when full signal data is available.",
    }[confidence]
    parts.append(conf_phrase)
    parts.append(f"Overall risk assessment: {level} ({score}/100).")
    return " ".join(parts)


def _session_recommendations(
    ip, score, level, lateral, attack_types,
    exploit_cve, yara_matches, vt_available, is_private,
    success_count, attacker_compromised,
) -> list:
    actions = []
    if success_count > 0:
        actions.append(f"CRITICAL: {success_count} successful authentication(s) detected. Immediately rotate any credentials that may have been used on the honeypot. Audit all systems where those credentials are valid.")
    if level == "CRITICAL":
        actions.append("IMMEDIATE: Escalate to incident response team — risk level is CRITICAL.")
        actions.append(f"IMMEDIATE: {'Isolate host' if is_private else 'Block'} {ip} {'from the network pending investigation.' if is_private else 'at perimeter firewall and WAF.'}")
    elif level == "HIGH":
        actions.append(f"{'Investigate host' if is_private else 'Block'} {ip} {'as a priority — high-risk internal activity detected.' if is_private else 'at firewall and add to threat intelligence blocklist.'}")
    elif level == "MEDIUM":
        actions.append(f"Monitor {ip} for escalation; consider adding to watchlist.")
    else:
        actions.append(f"Log and observe {ip}; no immediate action required.")
    if "brute_force" in attack_types:
        actions.append(f"Audit all authentication logs for {ip} — check for any successful logins that may have occurred before detection.")
    if "lateral_movement" in attack_types or lateral:
        actions.append(f"Review all SMB connections originating from {ip}. Check for unauthorized access to network shares and credential relay attacks.")
        actions.append("Audit Active Directory for abnormal privilege changes or new service accounts created around the time of this session.")
    if "exploitation" in attack_types and exploit_cve:
        actions.append(f"Verify patch status for {', '.join(exploit_cve)} on all systems reachable from {ip}. Scan for indicators of compromise if exploit succeeded.")
    if "malware_delivery" in attack_types:
        if yara_matches:
            actions.append(f"Quarantine all files from this session and submit to sandboxed analysis. YARA families matched: {', '.join(yara_matches)}.")
        if not vt_available:
            actions.append("Re-run VirusTotal lookups when quota resets — current verdict is incomplete.")
    if "post_exploitation" in attack_types:
        actions.append("Review executed commands in Cowrie session logs for persistence mechanisms, C2 beaconing, or credential harvesting.")
    if "reconnaissance" in attack_types:
        actions.append("Check for follow-up attacks — reconnaissance often precedes exploitation. Correlate this IP across all honeypot logs.")
    if "anonymized_attacker" in attack_types:
        actions.append("Flag as anonymized attacker in threat intelligence. Correlate with other sessions using the same Tor exit node / VPN range.")
    if "automated" in attack_types:
        actions.append("Attack used automated tooling — signatures may match known scanners. Check rate-limiting and WAF bot-detection rules.")
    if "persistent_attacker" in attack_types:
        actions.append(f"This attacker has targeted our platform before. Review historical sessions for {ip} and correlate TTPs.")
    if "compromised_host" in attack_types or attacker_compromised:
        actions.append(f"The attacker IP is likely a compromised zombie (vulnerable services exposed). Consider coordinated disclosure to the network owner via AbuseIPDB.")
    actions.append("Preserve all raw logs (Cowrie session, Zeek NTLM, Dionaea SQLite) for chain-of-custody and legal evidence (RFC 3161 timestamping).")
    return actions
