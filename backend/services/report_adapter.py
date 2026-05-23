"""
Adapter between forensic-engine v2.0.0 risk_score output and report template data shapes.

Scorer outputs (signal_breakdown JSONB from ip_risk_scores / forensic_sessions):
    {"reputation":          {"points": 11, "max": 15, "label": "...", "detail": "..."},
     "anonymization":       {"points": 10, "max": 10, ...},
     "threat_history":      {"points":  8, "max":  8, ...},
     "intent_volume":       {"points":  6, "max": 10, ...},
     "compromise_depth":    {"points": 12, "max": 15, ...},
     "exfiltration":        {"points":  4, "max":  8, ...},
     "lateral_movement":    {"points":  6, "max": 10, ...},
     "malware":             {"points":  6, "max": 12, ...},
     "mitre_sophistication":{"points":  8, "max": 12, ...}}

Report template (report.html / forenhive_rapport_v2.html) expects:
    [{"name": "IP Reputation", "points": 11, "max_points": 15, "detail": "..."}, ...]
"""

from typing import Dict, List


def adapt_signal_breakdown(breakdown: dict) -> List[Dict]:
    """Convert scorer signal_breakdown dict -> report template list."""
    result = []
    for key, sig in breakdown.items():
        result.append({
            "name":       sig.get("label", key.replace("_", " ").title()),
            "points":     sig.get("points", 0),
            "max_points": sig.get("max", 0),
            "detail":     sig.get("detail", ""),
        })
    return result


def adapt_recommendations(recs: list) -> List[Dict]:
    """Normalize recommendations to {priority, action, rationale} dicts."""
    result = []
    for r in recs:
        if isinstance(r, dict):
            result.append({
                "priority":  r.get("priority", "MEDIUM"),
                "action":    r.get("action", str(r)),
                "rationale": r.get("rationale", ""),
            })
        elif isinstance(r, str):
            priority = "IMMEDIATE" if "IMMEDIATE" in r.upper() else (
                "HIGH" if "HIGH" in r.upper() or r.startswith("🔴") else "MEDIUM"
            )
            result.append({
                "priority":  priority,
                "action":    r.lstrip("🔴🟠🟡 "),
                "rationale": "",
            })
    return result


def adapt_risk_data_for_report(risk_data: dict) -> dict:
    """Full adapter: ip_risk_scores row -> Jinja2 template dict."""
    breakdown  = risk_data.get("signal_breakdown", {})
    recs       = risk_data.get("recommendations", [])
    enrichment = risk_data.get("enrichment_snapshot", {})

    return {
        "risk_score":      risk_data.get("risk_score", 0),
        "risk_level":      risk_data.get("risk_level", "INFO"),
        "risk_confidence": risk_data.get("confidence", "LOW"),
        "signal_breakdown": adapt_signal_breakdown(breakdown) if isinstance(breakdown, dict) else breakdown,
        "risk_warnings":   risk_data.get("risk_warnings", []),
        "recommendations": adapt_recommendations(recs) if recs else [],
        "source_ip":       str(risk_data.get("source_ip", "")),
        "geo_country":     enrichment.get("country", "Unknown"),
        "geo_city":        enrichment.get("city", "Unknown"),
        "asn":             enrichment.get("asn", "Unknown"),
        "isp":             enrichment.get("org", ""),
        "abuse_score":     enrichment.get("abuse_score", 0),
        "honeypots_hit":    risk_data.get("honeypots_hit", []),
        "honeypot_count":   risk_data.get("honeypot_count", 0),
        "honeypot_summary": risk_data.get("honeypot_summary", {}),
    }
