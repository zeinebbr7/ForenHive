"""
Single source of truth for risk-score thresholds.

Imported by:
  - forensic-engine/risk_score_optimized.py  (level mapping)
  - forensic-engine/engine.py                (alert-index gate)
  - forensic-engine/config.py                (PROFILE_RISK_THRESHOLD default)
  - backend/config.py                        (risk_alert_threshold default)
  - chatbot/hive_chat.py                     (high-risk session query)
  - frontend/src/constants.js                (mirrored as RISK_* + riskLevel)

Any change here MUST be mirrored in frontend/src/constants.js.
"""

# Level cutoffs (numeric score >= cutoff → label)
CRITICAL = 80
HIGH     = 60
MEDIUM   = 40
LOW      = 20

# Operational thresholds derived from level cutoffs
ALERT_INDEX_MIN  = HIGH    # 60 — index forensic-alerts at HIGH and above
ALERT_NOTIFY_MIN = 75      # email/webhook notify cutoff (between HIGH and CRITICAL)
PROFILE_RISK_MIN = HIGH    # 60 — generate suspect profile at HIGH and above


def risk_level(score) -> str:
    """Map a numeric score (0-100) to canonical level label."""
    s = int(score or 0)
    if s >= CRITICAL: return "CRITICAL"
    if s >= HIGH:     return "HIGH"
    if s >= MEDIUM:   return "MEDIUM"
    if s >= LOW:      return "LOW"
    return "INFO"
