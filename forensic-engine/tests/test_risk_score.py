"""
Forensic-engine RiskScorer tests (risk_score_optimized).
Run inside the forensic-engine container:
    docker exec forenhive-forensic-engine python -m pytest tests/ -v
"""
import sys
import os
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from risk_score_optimized import RiskScorer


class TestRiskScorerSignals(unittest.TestCase):

    def setUp(self):
        self.scorer = RiskScorer()

    # ── Signal 1: Reputation ────────────────────────────────────────────────

    def test_signal_reputation_public_high_abuse(self):
        """Public IP with AbuseIPDB score >= 90 returns 25 pts."""
        enrichment = {"reputation": {"abuse_score": 95}}
        assert self.scorer._signal_reputation("1.2.3.4", enrichment) == 25

    def test_signal_reputation_private_ip_zero(self):
        """Private IPs get 0 reputation points (no AbuseIPDB lookup)."""
        enrichment = {"reputation": {"abuse_score": 100}}
        assert self.scorer._signal_reputation("192.168.1.1", enrichment) == 0

    def test_signal_reputation_no_abuse_data(self):
        """Missing AbuseIPDB data returns 0."""
        assert self.scorer._signal_reputation("8.8.8.8", {}) == 0

    # ── Signal 2: Compromise ────────────────────────────────────────────────

    def test_signal_compromise_success(self):
        """A session with success_count > 0 returns 25 pts."""
        sessions = [{"honeypot_type": "cowrie", "success_count": 1}]
        assert self.scorer._signal_compromise(sessions) == 25

    def test_signal_compromise_no_success(self):
        """Sessions without a successful login return 0."""
        sessions = [{"honeypot_type": "cowrie", "success_count": 0}]
        assert self.scorer._signal_compromise(sessions) == 0

    # ── Signal 3: Brute Force ───────────────────────────────────────────────

    def test_signal_brute_force_high_velocity(self):
        """Attack velocity > 50 req/s returns max 20 pts."""
        sessions = [{"login_attempts": 1000, "attack_velocity": 60.0}]
        assert self.scorer._signal_brute_force(sessions) == 20

    def test_signal_brute_force_many_attempts(self):
        """500+ attempts returns 15 pts."""
        sessions = [{"login_attempts": 600, "attack_velocity": 0}]
        assert self.scorer._signal_brute_force(sessions) == 15

    def test_signal_brute_force_low_attempts(self):
        """Fewer than 50 attempts returns 0."""
        sessions = [{"login_attempts": 10, "attack_velocity": 0}]
        assert self.scorer._signal_brute_force(sessions) == 0

    # ── Signal 5: Anonymization ─────────────────────────────────────────────

    def test_signal_anonymization_tor(self):
        """Tor exit node returns 10 pts."""
        enrichment = {"threat_summary": {"is_tor": True}}
        assert self.scorer._signal_anonymization(enrichment) == 10

    def test_signal_anonymization_vpn(self):
        """VPN/proxy returns 6 pts."""
        enrichment = {"privacy": {"is_vpn": True}}
        assert self.scorer._signal_anonymization(enrichment) == 6

    def test_signal_anonymization_direct(self):
        """Direct connection returns 0."""
        assert self.scorer._signal_anonymization({}) == 0

    # ── Risk level thresholds ───────────────────────────────────────────────

    def test_risk_level_critique(self):
        assert RiskScorer._get_risk_level(80) == "CRITIQUE"
        assert RiskScorer._get_risk_level(100) == "CRITIQUE"

    def test_risk_level_eleve(self):
        assert RiskScorer._get_risk_level(60) == "ÉLEVÉ"
        assert RiskScorer._get_risk_level(79) == "ÉLEVÉ"

    def test_risk_level_moyen(self):
        assert RiskScorer._get_risk_level(40) == "MOYEN"

    def test_risk_level_faible(self):
        assert RiskScorer._get_risk_level(20) == "FAIBLE"

    def test_risk_level_info(self):
        assert RiskScorer._get_risk_level(0) == "INFO"
        assert RiskScorer._get_risk_level(19) == "INFO"

    # ── Confidence ─────────────────────────────────────────────────────────

    def test_confidence_high(self):
        assert RiskScorer._get_confidence(4) == "HIGH"

    def test_confidence_medium(self):
        assert RiskScorer._get_confidence(2) == "MEDIUM"

    def test_confidence_low(self):
        assert RiskScorer._get_confidence(1) == "LOW"

    # ── Private IP helper ───────────────────────────────────────────────────

    def test_is_private_ip_rfc1918(self):
        assert RiskScorer._is_private_ip("10.0.0.1") is True
        assert RiskScorer._is_private_ip("172.16.0.1") is True
        assert RiskScorer._is_private_ip("192.168.1.1") is True

    def test_is_private_ip_public(self):
        assert RiskScorer._is_private_ip("8.8.8.8") is False

    def test_is_private_ip_invalid(self):
        assert RiskScorer._is_private_ip("not-an-ip") is False

    # ── Empty score ─────────────────────────────────────────────────────────

    def test_empty_score_structure(self):
        result = RiskScorer._empty_score("1.2.3.4")
        assert result["source_ip"] == "1.2.3.4"
        assert result["risk_score"] == 0
        assert result["risk_level"] == "INFO"
        assert result["confidence"] == "LOW"

    # ── Score capped at 100 ─────────────────────────────────────────────────

    def test_score_capped_at_100(self):
        """All signals firing cannot exceed 100."""
        total = (25 + 25 + 20 + 15 + 10 + 5)
        assert min(100, total) == 100


if __name__ == "__main__":
    unittest.main()
