"""
Single source of truth for risk-score thresholds.

v2.0.0 (May 2026):
  - Label cutoffs recalibrated for 9-signal scorer (was 80/60/40/20).
  - Operational thresholds DECOUPLED from labels — they're now standalone
    numbers, NOT derived from HIGH. Protects profiler / alerter from cost
    spikes when label scale shifts.
"""

# Label cutoffs (v2.0 calibration for 9-signal scorer)
CRITICAL = 70  # was 80
HIGH = 45  # was 60
MEDIUM = 25  # was 40
LOW = 10  # was 20

# Operational thresholds — INDEPENDENT of label cutoffs
ALERT_INDEX_MIN = 40
ALERT_NOTIFY_MIN = 60
PROFILE_RISK_MIN = 50


def risk_level(score) -> str:
    """Map a numeric score (0-100) to canonical level label."""
    s = int(score or 0)
    if s >= CRITICAL:
        return "CRITICAL"
    if s >= HIGH:
        return "HIGH"
    if s >= MEDIUM:
        return "MEDIUM"
    if s >= LOW:
        return "LOW"
    return "INFO"
