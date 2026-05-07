"""
ForenHive — Unified Risk Scorer (Option A)

One score per source_ip aggregating all honeypots (Cowrie, Dionaea, Galah)
within a configurable time window. 6-signal direct 0-100 scale.
"""

import json
import logging
from datetime import datetime
from typing import Dict, List

import config
import db_pool

log = logging.getLogger("risk_score_optimized")


class RiskScorer:
    """
    Simplified 6-signal risk scoring (0-100 direct).
    One score per source_ip aggregating all honeypots in time window.
    """

    def calculate_risk_score(self, source_ip: str, time_window_hours: int = 24) -> Dict:
        """
        Calculate unified risk score for an IP across all honeypots in time window.

        Args:
            source_ip: The attacker IP (e.g. '185.220.101.5')
            time_window_hours: Look back this many hours (default 24h)

        Returns:
            Dict with score (0-100), level, confidence, signals breakdown
        """
        log.info(f"Calculating risk score for {source_ip} (window: {time_window_hours}h)")

        try:
            all_sessions = self._query_sessions_by_ip(source_ip, time_window_hours)

            if not all_sessions:
                log.warning(f"No sessions found for {source_ip}")
                return self._empty_score(source_ip)

            log.info(f"Found {len(all_sessions)} sessions for {source_ip}")

            enrichment = self._query_enrichment(source_ip)

            signal_1 = self._signal_reputation(source_ip, enrichment)
            signal_2 = self._signal_compromise(all_sessions)
            signal_3 = self._signal_brute_force(all_sessions)
            signal_4 = self._signal_malware(all_sessions)
            signal_5 = self._signal_anonymization(enrichment)
            signal_6 = self._signal_sophistication(all_sessions, enrichment)

            signals = {
                "reputation":     signal_1,
                "compromise":     signal_2,
                "brute_force":    signal_3,
                "malware":        signal_4,
                "anonymization":  signal_5,
                "sophistication": signal_6,
            }

            risk_score  = min(100, sum(signals.values()))
            risk_level  = self._get_risk_level(risk_score)
            active_signals = sum(1 for v in signals.values() if v > 0)
            confidence  = self._get_confidence(active_signals)

            honeypots_hit = list({s["honeypot_type"] for s in all_sessions if s.get("honeypot_type")})
            honeypot_summary = {
                "cowrie":  len([s for s in all_sessions if s.get("honeypot_type") == "cowrie"]),
                "dionaea": len([s for s in all_sessions if s.get("honeypot_type") == "dionaea"]),
                "galah":   len([s for s in all_sessions if s.get("honeypot_type") == "galah"]),
            }

            signal_breakdown = {
                "reputation": {
                    "points": signal_1,
                    "max":    25,
                    "label":  "IP Reputation",
                    "detail": self._signal_detail_reputation(enrichment),
                },
                "compromise": {
                    "points": signal_2,
                    "max":    25,
                    "label":  "Compromise Confirmed",
                    "detail": self._signal_detail_compromise(all_sessions),
                },
                "brute_force": {
                    "points": signal_3,
                    "max":    20,
                    "label":  "Brute Force Automation",
                    "detail": self._signal_detail_brute_force(all_sessions),
                },
                "malware": {
                    "points": signal_4,
                    "max":    15,
                    "label":  "Malware Detected",
                    "detail": self._signal_detail_malware(all_sessions),
                },
                "anonymization": {
                    "points": signal_5,
                    "max":    10,
                    "label":  "Anonymization/Evasion",
                    "detail": self._signal_detail_anonymization(enrichment),
                },
                "sophistication": {
                    "points": signal_6,
                    "max":    5,
                    "label":  "Attack Sophistication",
                    "detail": self._signal_detail_sophistication(all_sessions, honeypots_hit),
                },
            }

            key_findings    = self._generate_key_findings(all_sessions, signals, enrichment)
            recommendations = self._generate_recommendations(risk_score, all_sessions)

            result = {
                "source_ip":     source_ip,
                "risk_score":    risk_score,
                "risk_level":    risk_level,
                "confidence":    confidence,
                "active_signals": active_signals,
                "timestamp":     datetime.utcnow().isoformat() + "Z",

                "signal_breakdown":  signal_breakdown,
                "honeypots_hit":     honeypots_hit,
                "honeypot_count":    len(honeypots_hit),
                "honeypot_summary":  honeypot_summary,
                "sessions_count":    len(all_sessions),

                "key_findings":    key_findings,
                "recommendations": recommendations,

                "enrichment_snapshot": {
                    "country":      enrichment.get("geo", {}).get("country"),
                    "asn":          enrichment.get("geo", {}).get("asn"),
                    "organization": enrichment.get("geo", {}).get("org"),
                    "is_tor":       enrichment.get("privacy", {}).get("is_tor", False),
                    "is_vpn":       enrichment.get("privacy", {}).get("is_vpn", False),
                    "is_hosting":   enrichment.get("privacy", {}).get("is_hosting", False),
                    "abuse_score":  enrichment.get("reputation", {}).get("abuse_score", 0),
                },
            }

            log.info(f"Risk score for {source_ip}: {risk_score}/{risk_level}/{confidence}")
            return result

        except Exception as e:
            log.error(f"Risk score calculation failed for {source_ip}: {e}", exc_info=True)
            raise

    # ── Signal 1: IP Reputation ───────────────────────────────────────────────

    def _signal_reputation(self, source_ip: str, enrichment: dict) -> int:
        """0-25 points. Public IP: AbuseIPDB score. Private IP: 0."""
        if self._is_private_ip(source_ip):
            return 0

        abuse_score = enrichment.get("reputation", {}).get("abuse_score", 0)
        if abuse_score >= 90:
            return 25
        elif abuse_score >= 70:
            return 18
        elif abuse_score >= 50:
            return 12
        elif abuse_score >= 30:
            return 6
        return 0

    # ── Signal 2: Compromise Confirmed ───────────────────────────────────────

    def _signal_compromise(self, all_sessions: list) -> int:
        """0-25 points. Did they successfully login/exploit any honeypot?"""
        for session in all_sessions:
            if session.get("success_count", 0) > 0:
                return 25
        return 0

    # ── Signal 3: Brute Force Automation ─────────────────────────────────────

    def _signal_brute_force(self, all_sessions: list) -> int:
        """0-20 points. Aggregate attempt count and velocity across sessions."""
        total_attempts = sum(s.get("login_attempts", 0) for s in all_sessions)
        max_velocity   = max(
            (s.get("attack_velocity", 0) for s in all_sessions), default=0
        )

        if max_velocity > 50:
            base_score = 20
        elif total_attempts >= 500:
            base_score = 15
        elif total_attempts >= 200:
            base_score = 10
        elif total_attempts >= 50:
            base_score = 5
        else:
            base_score = 0

        return base_score

    # ── Signal 4: Malware Detected ────────────────────────────────────────────

    def _signal_malware(self, all_sessions: list) -> int:
        """0-15 points. YARA matches and VirusTotal across all sessions."""
        for session in all_sessions:
            enrich  = session.get("enrichment_data") or {}
            yara    = enrich.get("yara_matches", []) if isinstance(enrich, dict) else []
            vt_mal  = enrich.get("vt_malicious", 0) if isinstance(enrich, dict) else 0

            if yara:
                return 10
            if vt_mal >= 30:
                return 10
            elif vt_mal >= 10:
                return 5

        return 0

    # ── Signal 5: Anonymization/Evasion ──────────────────────────────────────

    def _signal_anonymization(self, enrichment: dict) -> int:
        """0-10 points. Tor/VPN/proxy usage."""
        privacy  = enrichment.get("privacy", {}) or {}
        threat   = enrichment.get("threat_summary", {}) or {}

        is_tor   = threat.get("is_tor", False) or privacy.get("is_tor", False)
        is_vpn   = threat.get("is_vpn", False) or privacy.get("is_vpn", False)
        is_proxy = threat.get("is_proxy", False) or privacy.get("is_proxy", False)

        if is_tor:
            return 10
        elif is_vpn or is_proxy:
            return 6
        return 0

    # ── Signal 6: Attack Sophistication ──────────────────────────────────────

    def _signal_sophistication(self, all_sessions: list, enrichment: dict) -> int:
        """0-5 points. Kill chain stage + multi-honeypot coordination."""
        max_kill_chain = 0
        for session in all_sessions:
            kc = session.get("kill_chain_stage") or 0
            max_kill_chain = max(max_kill_chain, int(kc))

        if max_kill_chain >= 6:
            soph_pts = 5
        elif max_kill_chain >= 4:
            soph_pts = 3
        elif max_kill_chain >= 2:
            soph_pts = 1
        else:
            soph_pts = 0

        honeypot_types = {s.get("honeypot_type") for s in all_sessions if s.get("honeypot_type")}
        if len(honeypot_types) > 1:
            soph_pts = min(5, soph_pts + 2)

        return soph_pts

    # ── Database helpers ──────────────────────────────────────────────────────

    def _query_sessions_by_ip(self, source_ip: str, hours: int) -> list:
        """Query all sessions from this IP in time window."""
        import psycopg2.extras
        try:
            with db_pool.pooled_conn() as conn:
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
                        (source_ip, int(hours)),
                    )
                    return [dict(row) for row in cur.fetchall()]
        except Exception as e:
            log.error(f"Query sessions failed for {source_ip}: {e}")
            return []

    def _query_enrichment(self, source_ip: str) -> dict:
        """Query enrichment data from ip_enrichment_cache."""
        import psycopg2.extras
        try:
            with db_pool.pooled_conn() as conn:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    cur.execute(
                        "SELECT data FROM ip_enrichment_cache WHERE ip = %s LIMIT 1",
                        (source_ip,),
                    )
                    row = cur.fetchone()
                    if not row:
                        return {}
                    data = row["data"]
                    return data if isinstance(data, dict) else json.loads(data)
        except Exception as e:
            log.error(f"Query enrichment failed for {source_ip}: {e}")
            return {}

    # ── Utility helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        import ipaddress
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    @staticmethod
    def _get_risk_level(score: int) -> str:
        if score >= 80:
            return "CRITIQUE"
        elif score >= 60:
            return "ÉLEVÉ"
        elif score >= 40:
            return "MOYEN"
        elif score >= 20:
            return "FAIBLE"
        return "INFO"

    @staticmethod
    def _get_confidence(active_signals: int) -> str:
        if active_signals >= 4:
            return "HIGH"
        elif active_signals >= 2:
            return "MEDIUM"
        return "LOW"

    # ── Detail generators ─────────────────────────────────────────────────────

    def _signal_detail_reputation(self, enrichment: dict) -> str:
        abuse_score = enrichment.get("reputation", {}).get("abuse_score", 0)
        return f"AbuseIPDB score {abuse_score}/100"

    def _signal_detail_compromise(self, all_sessions: list) -> str:
        for s in all_sessions:
            if s.get("success_count", 0) > 0:
                return f"Login successful on {s.get('honeypot_type', 'unknown')}"
        return "No compromise detected"

    def _signal_detail_brute_force(self, all_sessions: list) -> str:
        total = sum(s.get("login_attempts", 0) for s in all_sessions)
        return f"{total} total login attempts across all honeypots"

    def _signal_detail_malware(self, all_sessions: list) -> str:
        for s in all_sessions:
            enrich = s.get("enrichment_data") or {}
            yara   = enrich.get("yara_matches", []) if isinstance(enrich, dict) else []
            if yara:
                return f"YARA match: {yara[0] if isinstance(yara[0], str) else yara[0].get('rule', 'unknown')}"
        return "No malware detected"

    def _signal_detail_anonymization(self, enrichment: dict) -> str:
        threat  = enrichment.get("threat_summary", {}) or {}
        privacy = enrichment.get("privacy", {}) or {}
        if threat.get("is_tor") or privacy.get("is_tor"):
            return "Tor exit node detected"
        elif threat.get("is_vpn") or privacy.get("is_vpn"):
            return "VPN/Proxy detected"
        return "Direct connection"

    def _signal_detail_sophistication(self, all_sessions: list, honeypots_hit: list) -> str:
        if len(honeypots_hit) > 1:
            return f"Multi-honeypot attack: {', '.join(honeypots_hit)}"
        return f"Single service attack: {honeypots_hit[0] if honeypots_hit else 'unknown'}"

    # ── Key findings and recommendations ─────────────────────────────────────

    def _generate_key_findings(self, all_sessions: list, signals: dict, enrichment: dict) -> list:
        findings = []
        if signals["compromise"] > 0:
            findings.append("Confirmed system compromise")
        if signals["brute_force"] > 0:
            findings.append("Automated brute force attack detected")
        if signals["malware"] > 0:
            findings.append("Malware/botnet payload detected")
        if signals["anonymization"] > 0:
            findings.append("Anonymization layer (Tor/VPN) used")
        if signals["sophistication"] > 0:
            findings.append("Multi-stage attack with lateral movement indicators")
        return findings

    def _generate_recommendations(self, risk_score: int, all_sessions: list) -> list:
        recommendations = []
        if risk_score >= 80:
            recommendations.append("IMMEDIATE: Block source IP at perimeter firewall")
            recommendations.append("IMMEDIATE: Force password reset on affected accounts")
        elif risk_score >= 60:
            recommendations.append("Block source IP at firewall")
            recommendations.append("Review access logs for unauthorized activity")
        recommendations.append("Export IOCs in STIX 2.1 format")
        return recommendations

    # ── Empty score ───────────────────────────────────────────────────────────

    @staticmethod
    def _empty_score(source_ip: str) -> dict:
        return {
            "source_ip":      source_ip,
            "risk_score":     0,
            "risk_level":     "INFO",
            "confidence":     "LOW",
            "active_signals": 0,
            "signal_breakdown": {},
            "honeypots_hit":  [],
            "honeypot_count": 0,
            "sessions_count": 0,
        }
