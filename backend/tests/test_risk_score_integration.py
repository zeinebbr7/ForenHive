"""
Unit tests for the risk-score module (v2.0.0, 9-signal model).

Imports `score_session` and `risk_level` from the forensic-engine package.
Tests are pure (no DB, no ES), exercising thresholds, boundaries, caps, and
bad inputs. This guards the cross-package import path as well as the scorer
contract the backend relies on.
"""

import sys
from pathlib import Path

import pytest

# Make forensic-engine importable regardless of where pytest is invoked.
_FE_DIR = Path(__file__).resolve().parents[2] / "forensic-engine"
if str(_FE_DIR) not in sys.path:
    sys.path.insert(0, str(_FE_DIR))

from risk_score import score_session  # noqa: E402
from risk_thresholds import (  # noqa: E402
    CRITICAL, HIGH, MEDIUM, LOW, risk_level,
)


# ─── level mapping ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("score,expected", [
    (0,            "INFO"),
    (LOW - 1,      "INFO"),
    (LOW,          "LOW"),
    (MEDIUM - 1,   "LOW"),
    (MEDIUM,       "MEDIUM"),
    (HIGH - 1,     "MEDIUM"),
    (HIGH,         "HIGH"),
    (CRITICAL - 1, "HIGH"),
    (CRITICAL,     "CRITICAL"),
    (100,          "CRITICAL"),
])
def test_risk_level_boundaries(score, expected):
    assert risk_level(score) == expected


def test_risk_level_handles_none_and_string():
    assert risk_level(None) == "INFO"
    assert risk_level("") == "INFO"


# ─── reputation signal (v2.0: 90→15, 70→11, 50→7, 25→4, else 0) ───────────────

@pytest.mark.parametrize("abuse,expected_points", [
    (0, 0), (24, 0),
    (25, 4), (49, 4),
    (50, 7), (69, 7),
    (70, 11), (89, 11),
    (90, 15), (100, 15),
])
def test_reputation_buckets(abuse, expected_points):
    r = score_session({"abuse_score": abuse})
    assert r.signal_breakdown["reputation"]["points"] == expected_points


def test_reputation_clamps_out_of_bounds():
    assert score_session({"abuse_score": -50}).signal_breakdown["reputation"]["points"] == 0
    assert score_session({"abuse_score": 999}).signal_breakdown["reputation"]["points"] == 15


def test_reputation_skipped_for_private_ip():
    r = score_session({"abuse_score": 95, "is_private": True})
    rep = r.signal_breakdown["reputation"]
    assert rep["points"] == 0
    assert rep["skipped"] is True
    assert rep["skip_reason"] == "private_ip"


# ─── intent_volume signal (was brute_force) ───────────────────────────────────

def test_intent_volume_zero_when_idle():
    assert score_session({}).signal_breakdown["intent_volume"]["points"] == 0


def test_intent_volume_scales_with_attempts_and_velocity():
    low  = score_session({"honeypot_type": "cowrie", "login_attempts": 10})
    high = score_session({"honeypot_type": "cowrie", "login_attempts": 10,
                          "attack_velocity": 100.0})
    assert high.signal_breakdown["intent_volume"]["points"] > \
        low.signal_breakdown["intent_volume"]["points"]


def test_intent_volume_capped_at_10():
    r = score_session({"honeypot_type": "cowrie", "login_attempts": 1_000_000,
                       "attack_velocity": 9999.0,
                       "http_paths": ["/admin", "/.env", "/wp-admin"]})
    assert r.signal_breakdown["intent_volume"]["points"] == 10


# ─── compromise_depth signal (was compromise) ─────────────────────────────────

def test_compromise_zero_when_no_success_or_files():
    assert score_session({"success_count": 0}).signal_breakdown["compromise_depth"]["points"] == 0


def test_compromise_scores_on_success():
    r = score_session({"success_count": 1})
    assert r.signal_breakdown["compromise_depth"]["points"] >= 5


def test_compromise_capped_at_15():
    r = score_session({
        "success_count": 999, "command_count": 999,
        "commands": ["cat /etc/shadow", "rm -rf /", "ssh root@x"],
        "file_download_count": 999,
    })
    assert r.signal_breakdown["compromise_depth"]["points"] == 15


# ─── input validation regressions ────────────────────────────────────────────

def test_empty_dict_returns_zero_score():
    r = score_session({})
    assert r.risk_score == 0
    assert r.risk_level == "INFO"


def test_none_input_is_safe():
    r = score_session(None)  # type: ignore[arg-type]
    assert r.risk_score == 0
    assert r.risk_level == "INFO"


def test_none_field_values_are_safe():
    # Every numeric/collection field passed as None — must coerce, not crash.
    r = score_session({
        "abuse_score": None,
        "success_count": None,
        "login_attempts": None,
        "attack_velocity": None,
        "vt_malicious": None,
        "yara_matches": None,
        "honeypot_types_hit": None,
        "mitre_techniques": None,
        "shodan_vulns": None,
        "exploit_cve": None,
        "commands": None,
        "http_paths": None,
    })
    assert r.risk_score == 0


def test_score_capped_at_100():
    # Saturate every signal — final score must never exceed 100.
    r = score_session({
        "abuse_score": 100, "is_tor": True, "shodan_vulns": ["a", "b"],
        "previously_seen": True, "previous_sessions": 1000,
        "is_abuser_listed": True, "threat_tier": "high",
        "geo_country_code": "KP",
        "honeypot_type": "cowrie", "login_attempts": 10000,
        "attack_velocity": 999.0, "http_paths": ["/admin", "/.env"],
        "success_count": 100, "command_count": 100,
        "commands": ["cat /etc/shadow", "rm -rf /", "ssh user@x"],
        "file_download_count": 50, "exfil_bytes": 1024 * 1024 * 1024,
        "exploit_cve": ["CVE-1"], "smb_share_enum": True, "epmapper_prescan": 5,
        "honeypot_types_hit": ["cowrie", "dionaea", "galah"], "destination_port": 445,
        "yara_matches": [{"rule": "X", "severity": "critical"}], "vt_malicious": 50,
        "mitre_techniques": ["T1110.001", "T1486", "T1105", "T1190", "T1210", "T1046"],
        "kill_chain_stage": 9,
    })
    assert r.risk_score == 100
    assert r.risk_level == "CRITICAL"


# ─── confidence (v2.0: ≥5 active HIGH, ≥3 MEDIUM, else LOW) ────────────────────

def test_confidence_scales_with_active_signals():
    low = score_session({"abuse_score": 30})  # 1 active
    assert low.confidence == "LOW"

    mid = score_session({"abuse_score": 30, "is_tor": True,  # 3 active
                         "previously_seen": True, "previous_sessions": 4})
    assert mid.confidence == "MEDIUM"

    hi = score_session({  # 5+ active
        "abuse_score": 30, "is_tor": True,
        "previously_seen": True, "previous_sessions": 4,
        "honeypot_type": "cowrie", "login_attempts": 50,
        "success_count": 2, "commands": ["whoami"],
        "exfil_bytes": 100 * 1024,
    })
    assert hi.confidence == "HIGH"
