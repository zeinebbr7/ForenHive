"""
Unit tests for the risk-score module.

Imports `score_session_from_data` and `risk_level` from the forensic-engine
package. Tests are pure (no DB, no ES), exercising thresholds, boundaries,
caps, and bad inputs.
"""

import sys
from pathlib import Path

import pytest

# Make forensic-engine importable regardless of where pytest is invoked.
_FE_DIR = Path(__file__).resolve().parents[2] / "forensic-engine"
if str(_FE_DIR) not in sys.path:
    sys.path.insert(0, str(_FE_DIR))

from risk_score_optimized import score_session_from_data  # noqa: E402
from risk_thresholds import (  # noqa: E402
    CRITICAL, HIGH, MEDIUM, LOW, risk_level,
)


# ─── level mapping ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("score,expected", [
    (0,           "INFO"),
    (LOW - 1,     "INFO"),
    (LOW,         "LOW"),
    (MEDIUM - 1,  "LOW"),
    (MEDIUM,      "MEDIUM"),
    (HIGH - 1,    "MEDIUM"),
    (HIGH,        "HIGH"),
    (CRITICAL - 1, "HIGH"),
    (CRITICAL,    "CRITICAL"),
    (100,         "CRITICAL"),
])
def test_risk_level_boundaries(score, expected):
    assert risk_level(score) == expected


def test_risk_level_handles_none_and_string():
    assert risk_level(None) == "INFO"
    assert risk_level("") == "INFO"


# ─── reputation signal ───────────────────────────────────────────────────────

@pytest.mark.parametrize("abuse,expected_points", [
    (0, 0), (29, 0), (30, 6), (49, 6), (50, 12), (69, 12),
    (70, 18), (89, 18), (90, 25), (100, 25),
])
def test_reputation_buckets(abuse, expected_points):
    r = score_session_from_data({"abuse_score": abuse})
    assert r["signal_breakdown"]["reputation"]["points"] == expected_points


def test_reputation_clamps_out_of_bounds():
    # Negative and >100 must clamp into the valid range.
    assert score_session_from_data({"abuse_score": -50})["signal_breakdown"]["reputation"]["points"] == 0
    assert score_session_from_data({"abuse_score": 999})["signal_breakdown"]["reputation"]["points"] == 25


def test_reputation_zero_for_private_ip():
    r = score_session_from_data({"abuse_score": 95, "is_private": True})
    assert r["signal_breakdown"]["reputation"]["points"] == 0


# ─── brute-force signal ───────────────────────────────────────────────────────

@pytest.mark.parametrize("attempts,velocity,expected", [
    (0, 0, 0),
    (49, 0, 0),
    (50, 0, 5),
    (200, 0, 10),
    (500, 0, 15),
    (10, 60.0, 20),       # velocity dominates
    (1000, 100.0, 20),
])
def test_brute_force_buckets(attempts, velocity, expected):
    r = score_session_from_data({"login_attempts": attempts, "attack_velocity": velocity})
    assert r["signal_breakdown"]["brute_force"]["points"] == expected


# ─── compromise signal ───────────────────────────────────────────────────────

def test_compromise_zero_when_no_success():
    assert score_session_from_data({"success_count": 0})["signal_breakdown"]["compromise"]["points"] == 0


def test_compromise_25_when_any_success():
    assert score_session_from_data({"success_count": 1})["signal_breakdown"]["compromise"]["points"] == 25
    assert score_session_from_data({"success_count": 99})["signal_breakdown"]["compromise"]["points"] == 25


# ─── input validation regressions ────────────────────────────────────────────

def test_empty_dict_returns_zero_score():
    r = score_session_from_data({})
    assert r["score"] == 0
    assert r["level"] == "INFO"


def test_none_input_is_safe():
    r = score_session_from_data(None)  # type: ignore[arg-type]
    assert r["score"] == 0
    assert r["level"] == "INFO"


def test_none_field_values_are_safe():
    # Every numeric field passed as None — must coerce to 0, not crash.
    r = score_session_from_data({
        "abuse_score": None,
        "success_count": None,
        "login_attempts": None,
        "attack_velocity": None,
        "vt_malicious": None,
        "yara_matches": None,
        "honeypot_types_hit": None,
    })
    assert r["score"] == 0


def test_score_capped_at_100():
    # Saturate every signal — final score must never exceed 100.
    r = score_session_from_data({
        "abuse_score": 100,
        "success_count": 5,
        "login_attempts": 10000,
        "attack_velocity": 1000.0,
        "yara_matches": ["Mirai_Botnet"],
        "is_tor": True,
        "honeypot_types_hit": ["cowrie", "dionaea", "galah"],
    })
    assert r["score"] <= 100
    assert r["score"] >= CRITICAL
    assert r["level"] == "CRITICAL"


# ─── confidence ──────────────────────────────────────────────────────────────

def test_confidence_scales_with_active_signals():
    low = score_session_from_data({"abuse_score": 30})
    assert low["confidence"] == "LOW"

    mid = score_session_from_data({"abuse_score": 30, "success_count": 1})
    assert mid["confidence"] == "MEDIUM"

    hi = score_session_from_data({
        "abuse_score": 30, "success_count": 1,
        "login_attempts": 100, "is_tor": True,
    })
    assert hi["confidence"] == "HIGH"
