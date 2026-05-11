"""
Forensic-engine risk_score tests.
Run inside the forensic-engine container:
    docker compose run --rm forensic-engine python -m pytest tests/ -v
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from risk_score import calculate_risk_score


def test_lateral_movement_external_ip_smb_share_enum():
    """BUG-012: smb_share_enum=True must set lateral_movement=True even on a public IP."""
    result = calculate_risk_score({
        "source_ip": "89.248.167.131",  # public IP — not private
        "smb_share_enum": True,
        "failed_auth_count": 5,
    })
    assert result["lateral_movement"] is True, (
        "lateral_movement must be True when smb_share_enum=True on external IP"
    )


def test_score_uncapped_in_result():
    """BUG-029: score_uncapped must be present and >= score when signals exceed 100."""
    result = calculate_risk_score({
        "source_ip": "89.248.167.131",
        "failed_auth_count": 500,
        "abuseipdb_score": 100,
        "is_tor": True,
        "yara_match": "Emotet",
        "smb_share_enum": True,
        "exploit_cve": "CVE-2021-44228",
        "mitre_techniques": ["T1110", "T1078", "T1059"],
        "country_iso": "KP",
        "command_count": 500,
        "download_attempt": True,
    })
    assert "score_uncapped" in result, "score_uncapped must be in result dict"
    assert result["score"] <= 100, "score must be capped at 100"
    assert result["score_uncapped"] >= result["score"], (
        "score_uncapped must be >= capped score"
    )


def test_lateral_movement_via_attack_types():
    """BUG-012: lateral_movement in attack_types (not just smb_share_enum) triggers flag."""
    result = calculate_risk_score({
        "source_ip": "93.184.216.34",  # example.com — public
        "smb_share_enum": True,        # triggers attack_types.add("lateral_movement")
        "failed_auth_count": 0,
    })
    assert "lateral_movement" in result["attack_types"]
    assert result["lateral_movement"] is True
