"""
ForenHive Unified Risk Scorer — v2.0
6-signal risk scoring: one score per source_ip aggregating all honeypots.

Signals (0-100 total):
  1. IP Reputation        (0-25)  — AbuseIPDB score
  2. Compromise Confirmed (0-25)  — successful login/exploit
  3. Brute Force          (0-20)  — attempt volume + velocity
  4. Malware Detected     (0-15)  — YARA + VirusTotal
  5. Anonymization        (0-10)  — Tor/VPN + critical port targeting
  6. Sophistication       (0-5)   — kill chain depth + multi-honeypot
"""

import ipaddress
import json
import logging
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

            if any(isinstance(m, dict) and m.get("severity") == "CRITICAL" for m in yara):
                return 15
            if any(isinstance(m, dict) and m.get("severity") == "HIGH" for m in yara):
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

        if ports_targeted & critical_ports:
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
