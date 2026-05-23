"""Tests for risk_score.py v2.0.0 (9-signal model)."""
import pytest

from risk_score import (
    score_session, score_ip, SCORE_VERSION,
    _signal_reputation, _signal_anonymization, _signal_threat_history,
    _signal_intent_volume, _signal_compromise_depth, _signal_exfiltration,
    _signal_lateral_movement, _signal_malware, _signal_mitre_sophistication,
)


_EXPECTED_SIGNALS = {
    "reputation", "anonymization", "threat_history",
    "intent_volume", "compromise_depth", "exfiltration",
    "lateral_movement", "malware", "mitre_sophistication",
}


# ── Signal 1: reputation ──────────────────────────────────────────────────────
@pytest.mark.parametrize("abuse,expected", [
    (95, 15), (90, 15),
    (70, 11), (89, 11),
    (50, 7),  (69, 7),
    (25, 4),  (49, 4),
    (24, 0),  (0, 0),
])
def test_reputation_buckets(abuse, expected):
    s = _signal_reputation({"abuse_score": abuse})
    assert s.points == expected
    assert s.max_points == 15
    assert s.category == "who"


def test_reputation_private_skipped():
    s = _signal_reputation({"abuse_score": 99, "is_private": True})
    assert s.skipped and s.skip_reason == "private_ip"
    assert s.points == 0


def test_reputation_clamps_negative_and_overflow():
    assert _signal_reputation({"abuse_score": -50}).points == 0
    assert _signal_reputation({"abuse_score": 9999}).points == 15


def test_reputation_evidence_populated_when_scoring():
    s = _signal_reputation({"abuse_score": 95, "abuse_total_reports": 12,
                            "abuse_distinct_users": 5,
                            "abuse_categories": ["ssh-bruteforce"]})
    assert s.evidence["abuse_score"] == 95
    assert s.evidence["total_reports"] == 12
    assert s.evidence["distinct_users"] == 5
    assert s.evidence["categories"] == ["ssh-bruteforce"]


# ── Signal 2: anonymization ───────────────────────────────────────────────────
def test_anonymization_bogon_beats_tor():
    s = _signal_anonymization({"is_bogon": True, "is_tor": True})
    assert s.points == 10
    assert "bogon" in s.detail


def test_anonymization_tor():
    s = _signal_anonymization({"is_tor": True})
    assert s.points == 10
    assert "Tor" in s.detail


def test_anonymization_vpn_proxy():
    assert _signal_anonymization({"is_vpn": True}).points == 6
    assert _signal_anonymization({"is_proxy": True}).points == 6


def test_anonymization_datacenter():
    assert _signal_anonymization({"is_datacenter": True}).points == 3


def test_anonymization_direct():
    assert _signal_anonymization({}).points == 0


def test_anonymization_private_skipped():
    s = _signal_anonymization({"is_tor": True, "is_private": True})
    assert s.skipped and s.points == 0


# ── Signal 3: threat_history ──────────────────────────────────────────────────
def test_threat_history_clean():
    assert _signal_threat_history({}).points == 0


def test_threat_history_recidivism():
    s = _signal_threat_history({"previously_seen": True, "previous_sessions": 8})
    assert s.points > 0


def test_threat_history_sanctioned_cc():
    s = _signal_threat_history({"geo_country_code": "KP"})
    assert s.points >= 2


def test_threat_history_high_threat_cc():
    s = _signal_threat_history({"geo_country_code": "RU"})
    assert s.points >= 1


def test_threat_history_shodan_vulns():
    s = _signal_threat_history({"shodan_vulns": ["CVE-2023-1", "CVE-2023-2", "CVE-2023-3"]})
    assert s.points >= 2  # capped at 2


def test_threat_history_caps_at_8():
    s = _signal_threat_history({
        "previously_seen": True, "previous_sessions": 1000,
        "is_abuser_listed": True, "threat_tier": "high",
        "geo_country_code": "KP",
        "shodan_vulns": ["a", "b", "c"],
    })
    assert s.points == 8


# ── Signal 4: intent_volume ───────────────────────────────────────────────────
def test_intent_volume_zero():
    assert _signal_intent_volume({}).points == 0


def test_intent_volume_cowrie_full_weight():
    s = _signal_intent_volume({"honeypot_type": "cowrie", "login_attempts": 100,
                               "attack_velocity": 60.0})
    assert s.points > 0
    assert s.evidence["honeypot_type"] == "cowrie"


def test_intent_volume_velocity_bonus():
    low  = _signal_intent_volume({"honeypot_type": "cowrie", "login_attempts": 10})
    high = _signal_intent_volume({"honeypot_type": "cowrie", "login_attempts": 10,
                                  "attack_velocity": 100.0})
    assert high.points > low.points


def test_intent_volume_scan_paths_in_http_and_commands():
    s = _signal_intent_volume({
        "honeypot_type": "galah", "login_attempts": 5,
        "http_paths": ["/admin", "/wp-admin"],
        "commands": ["curl /.env"],
    })
    assert len(s.evidence["scan_paths_hit"]) >= 3


def test_intent_volume_caps_at_10():
    s = _signal_intent_volume({
        "honeypot_type": "cowrie", "login_attempts": 1_000_000,
        "attack_velocity": 9999.0,
        "http_paths": _SCAN_PATHS_FULL_LIST(),
    })
    assert s.points == 10


def _SCAN_PATHS_FULL_LIST():
    from risk_score import _SCAN_PATHS
    return list(_SCAN_PATHS)


# ── Signal 5: compromise_depth ────────────────────────────────────────────────
def test_compromise_zero_when_no_success_or_files():
    s = _signal_compromise_depth({"success_count": 0})
    assert s.points == 0
    assert "no successful" in s.detail


def test_compromise_authentication_pts():
    s = _signal_compromise_depth({"success_count": 1})
    assert s.points >= 5  # int(5*log2(2)) = 5


def test_compromise_command_quality_credential():
    s = _signal_compromise_depth({"success_count": 1, "commands": ["cat /etc/shadow"]})
    assert "credential-access" in s.evidence["command_quality_tags"]
    assert s.points >= 5 + 3


def test_compromise_command_quality_destructive():
    s = _signal_compromise_depth({"success_count": 1, "commands": ["rm -rf /var"]})
    assert "destructive" in s.evidence["command_quality_tags"]


def test_compromise_command_quality_lateral():
    s = _signal_compromise_depth({"success_count": 1, "commands": ["ssh root@10.0.0.5"]})
    assert "lateral-cmd" in s.evidence["command_quality_tags"]


def test_compromise_file_downloads_count_with_no_success():
    s = _signal_compromise_depth({"success_count": 0, "file_download_count": 5})
    assert s.points >= 3  # ingress capped at 3


def test_compromise_caps_at_15():
    s = _signal_compromise_depth({
        "success_count": 999, "command_count": 999,
        "commands": ["cat /etc/shadow", "rm -rf /", "ssh root@x"],
        "file_download_count": 999,
    })
    assert s.points == 15


def test_compromise_precomputed_tags_used():
    """IP-mode: tags pre-aggregated, commands empty — quality bypasses pattern matching."""
    s = _signal_compromise_depth({
        "success_count": 1, "commands": [],
        "command_quality_tags": ["credential-access", "destructive"],
    })
    assert s.evidence["command_quality_tags"] == ["credential-access", "destructive"]
    assert s.points >= 5 + 4


def test_compromise_empty_precomputed_falls_through():
    """Empty precomputed list should fall through to pattern matching."""
    s = _signal_compromise_depth({
        "success_count": 1, "commands": ["cat /etc/shadow"],
        "command_quality_tags": [],
    })
    assert "credential-access" in s.evidence["command_quality_tags"]


# ── Signal 6: exfiltration ────────────────────────────────────────────────────
def test_exfil_zero():
    assert _signal_exfiltration({}).points == 0


def test_exfil_uses_exfil_bytes_not_payload():
    s = _signal_exfiltration({"exfil_bytes": 100 * 1024})  # ~100KB
    assert s.points == 4


def test_exfil_caps_at_8():
    s = _signal_exfiltration({"exfil_bytes": 10 * 1024 * 1024 * 1024})  # 10GB
    assert s.points == 8


def test_exfil_size_string_units():
    assert "KB" in _signal_exfiltration({"exfil_bytes": 100 * 1024}).detail
    assert "MB" in _signal_exfiltration({"exfil_bytes": 5 * 1024 * 1024}).detail
    assert "GB" in _signal_exfiltration({"exfil_bytes": 2 * 1024 * 1024 * 1024}).detail


# ── Signal 7: lateral_movement ────────────────────────────────────────────────
def test_lateral_none():
    assert _signal_lateral_movement({}).points == 0


def test_lateral_cve():
    s = _signal_lateral_movement({"exploit_cve": ["CVE-2017-0144"]})
    assert s.points >= 4


def test_lateral_smb_share():
    s = _signal_lateral_movement({"smb_share_enum": True})
    assert s.points >= 2


def test_lateral_multi_honeypot():
    s = _signal_lateral_movement({"honeypot_types_hit": ["cowrie", "dionaea", "galah"]})
    assert s.points >= 2


def test_lateral_critical_port_3389():
    s = _signal_lateral_movement({"destination_port": 3389})
    assert s.points >= 2
    assert s.evidence["destination_port"] == 3389


def test_lateral_non_critical_port_no_pts():
    s = _signal_lateral_movement({"destination_port": 8080})
    assert s.evidence["destination_port"] is None


def test_lateral_caps_at_10():
    s = _signal_lateral_movement({
        "exploit_cve": ["CVE-1", "CVE-2"], "smb_share_enum": True,
        "epmapper_prescan": 5, "honeypot_types_hit": ["a", "b", "c"],
        "destination_port": 445,
    })
    assert s.points == 10


# ── Signal 8: malware ─────────────────────────────────────────────────────────
def test_malware_clean():
    assert _signal_malware({}).points == 0


def test_malware_yara_with_severity():
    s = _signal_malware({"yara_matches": [{"rule": "Mirai", "severity": "critical"}]})
    assert s.points >= 6


def test_malware_yara_legacy_string():
    """Legacy List[str] format should be treated as medium severity."""
    s = _signal_malware({"yara_matches": ["Mirai_Botnet"]})
    assert s.points >= 2  # medium severity


def test_malware_vt_only():
    assert _signal_malware({"vt_malicious": 25}).points == 6
    assert _signal_malware({"vt_malicious": 12}).points == 4
    assert _signal_malware({"vt_malicious": 3}).points == 2


def test_malware_yara_plus_vt_additive():
    s = _signal_malware({
        "yara_matches": [{"rule": "X", "severity": "high"}],  # 4
        "vt_malicious": 25,  # 6
    })
    assert s.points == 10  # additive 4+6, under cap 12


def test_malware_caps_at_12():
    s = _signal_malware({
        "yara_matches": [{"rule": "X", "severity": "critical"}],  # 6
        "vt_malicious": 999,  # 6
    })
    assert s.points == 12


# ── Signal 9: mitre_sophistication ────────────────────────────────────────────
def test_mitre_none():
    assert _signal_mitre_sophistication({}).points == 0


def test_mitre_techniques_str_list():
    s = _signal_mitre_sophistication({"mitre_techniques": ["T1110.001", "T1078"]})
    assert s.points >= 2


def test_mitre_techniques_dict_list():
    s = _signal_mitre_sophistication({"mitre_techniques": [{"id": "T1110.001"}, {"id": "T1078"}]})
    assert s.points >= 2


def test_mitre_distinct_tactics():
    s = _signal_mitre_sophistication({
        "mitre_techniques": ["T1110.001", "T1486"],  # credential_access + impact
    })
    assert len(s.evidence["distinct_tactics"]) >= 2


def test_mitre_stage_bonus():
    s = _signal_mitre_sophistication({"kill_chain_stage": 8})
    assert s.points >= 4  # stage//2 = 4


def test_mitre_caps_at_12():
    s = _signal_mitre_sophistication({
        "mitre_techniques": ["T1110.001", "T1078", "T1105", "T1190",
                              "T1486", "T1210", "T1046"],
        "kill_chain_stage": 99,
    })
    assert s.points == 12


# ── Orchestrator: score_session ───────────────────────────────────────────────
def test_score_session_empty_dict():
    r = score_session({})
    assert r.risk_score == 0
    assert r.risk_level == "INFO"
    assert r.confidence == "LOW"
    assert r.score_version == SCORE_VERSION
    assert set(r.signal_breakdown.keys()) == _EXPECTED_SIGNALS


def test_score_session_non_dict():
    r = score_session(None)  # type: ignore[arg-type]
    assert r.risk_score == 0


def test_score_session_schema_contract():
    r = score_session({"abuse_score": 50})
    for sid, sd in r.signal_breakdown.items():
        assert sid in _EXPECTED_SIGNALS
        assert "points" in sd
        assert "max_points" in sd
        assert "label" in sd
        assert "category" in sd
        assert "detail" in sd
        assert "evidence" in sd
        assert "skipped" in sd
        assert "skip_reason" in sd


def test_score_session_caps_at_100():
    r = score_session({
        "abuse_score": 100, "is_tor": True, "shodan_vulns": ["a", "b"],
        "previously_seen": True, "previous_sessions": 1000,
        "is_abuser_listed": True, "threat_tier": "high",
        "geo_country_code": "KP",
        "honeypot_type": "cowrie", "login_attempts": 10000,
        "attack_velocity": 999, "http_paths": ["/admin", "/.env"],
        "success_count": 100, "command_count": 100,
        "commands": ["cat /etc/shadow", "rm -rf /", "ssh user@x"],
        "file_download_count": 50,
        "exfil_bytes": 1024 * 1024 * 1024,
        "exploit_cve": ["CVE-1"], "smb_share_enum": True,
        "epmapper_prescan": 5,
        "honeypot_types_hit": ["a", "b", "c"], "destination_port": 445,
        "yara_matches": [{"rule": "X", "severity": "critical"}],
        "vt_malicious": 50,
        "mitre_techniques": ["T1110.001", "T1486", "T1105", "T1190", "T1210", "T1046"],
        "kill_chain_stage": 9,
    })
    assert r.risk_score == 100


def test_score_session_confidence_thresholds():
    # 1 active signal → LOW
    r1 = score_session({"abuse_score": 50})
    assert r1.confidence == "LOW"
    # 3 active signals → MEDIUM
    r3 = score_session({"abuse_score": 50, "is_tor": True,
                        "previously_seen": True, "previous_sessions": 4})
    assert r3.confidence == "MEDIUM"
    # 5+ active → HIGH
    r5 = score_session({
        "abuse_score": 50, "is_tor": True, "previously_seen": True,
        "previous_sessions": 4, "honeypot_type": "cowrie",
        "login_attempts": 50, "success_count": 2,
        "commands": ["whoami"], "exfil_bytes": 100 * 1024,
    })
    assert r5.confidence == "HIGH"


def test_score_session_private_ip_other_signals_still_work():
    r = score_session({
        "is_private": True,
        "honeypot_type": "cowrie", "login_attempts": 100,
        "success_count": 5, "commands": ["cat /etc/shadow"],
    })
    # reputation and anonymization should be skipped
    assert r.signal_breakdown["reputation"]["skipped"]
    assert r.signal_breakdown["anonymization"]["skipped"]
    # but compromise_depth should fire
    assert r.signal_breakdown["compromise_depth"]["points"] > 0


def test_score_session_version_is_2_0_0():
    assert score_session({}).score_version == "2.0.0"


def test_score_session_scorer_mode():
    assert score_session({}).scorer_mode == "session"
    assert score_session({}).sessions_aggregated is None


# ── Orchestrator: score_ip ────────────────────────────────────────────────────
def test_score_ip_empty_sessions():
    r = score_ip("1.2.3.4", [], {})
    assert r.risk_score == 0
    assert r.risk_level == "INFO"
    assert r.scorer_mode == "ip_aggregate"
    assert r.sessions_aggregated == 0


def test_score_ip_aggregates_login_attempts():
    sessions = [
        {"honeypot_type": "cowrie", "login_attempts": 50, "success_count": 1},
        {"honeypot_type": "cowrie", "login_attempts": 30, "success_count": 0},
    ]
    r = score_ip("1.2.3.4", sessions, {})
    assert r.scorer_mode == "ip_aggregate"
    assert r.sessions_aggregated == 2
    iv = r.signal_breakdown["intent_volume"]
    assert iv["evidence"]["login_attempts"] == 80


def test_score_ip_unions_mitre_techniques():
    sessions = [
        {"mitre_techniques": ["T1110.001"], "kill_chain_stage": 2},
        {"mitre_techniques": ["T1078", "T1486"], "kill_chain_stage": 5},
    ]
    r = score_ip("1.2.3.4", sessions, {})
    ms = r.signal_breakdown["mitre_sophistication"]
    assert set(ms["evidence"]["mitre_techniques"]) == {"T1110.001", "T1078", "T1486"}
    assert ms["evidence"]["kill_chain_stage"] == 5


def test_score_ip_passes_enrichment_who_signals():
    sessions = [{"honeypot_type": "cowrie", "login_attempts": 1}]
    enrichment = {
        "reputation":      {"abuse_score": 95},
        "threat_summary":  {"is_tor": True, "tier": "high"},
        "geo":             {"country_code": "KP"},
        "infrastructure":  {"vulns": ["CVE-2023-X"]},
    }
    r = score_ip("1.2.3.4", sessions, enrichment)
    assert r.signal_breakdown["reputation"]["points"] == 15
    assert r.signal_breakdown["anonymization"]["points"] == 10
    assert r.signal_breakdown["threat_history"]["points"] >= 3


def test_score_ip_command_quality_tags_aggregated():
    sessions = [
        {"honeypot_type": "cowrie", "success_count": 1,
         "command_quality_tags": ["credential-access"]},
        {"honeypot_type": "cowrie", "success_count": 1,
         "command_quality_tags": ["destructive"]},
    ]
    r = score_ip("1.2.3.4", sessions, {})
    cd = r.signal_breakdown["compromise_depth"]
    tags = set(cd["evidence"]["command_quality_tags"])
    assert tags == {"credential-access", "destructive"}


def test_score_ip_multi_honeypot_lateral():
    sessions = [
        {"honeypot_type": "cowrie"},
        {"honeypot_type": "dionaea"},
        {"honeypot_type": "galah"},
    ]
    r = score_ip("1.2.3.4", sessions, {})
    lm = r.signal_breakdown["lateral_movement"]
    assert lm["points"] >= 2  # 3+ honeypots
