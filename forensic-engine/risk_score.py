"""
ForenHive Forensic Engine — Risk Score Calculator
Produces a 0-100 score per session based on multiple forensic signals.
"""


# Ports that indicate attacks on critical services
CRITICAL_PORTS = {445, 1433, 27017, 3306, 5432, 6379, 2375, 9200}


def calculate_risk_score(session_data: dict) -> int:
    """
    Calculate risk score (0-100) from aggregated session forensic data.

    Expected keys in session_data:
      abuse_score       int  (0-100 from AbuseIPDB)
      is_tor            bool
      is_vpn            bool
      is_proxy          bool
      yara_matches      list (YARA rule names matched)
      vt_malicious      int  (VirusTotal malicious engine count)
      login_attempts    int  (total login attempts in session)
      destination_port  int  (primary target port)
      honeypot_type     str  (cowrie / dionaea / galah / zeek)
      command_count     int  (commands executed in cowrie session)
      exfil_bytes       int  (bytes transferred / network.bytes)
    """
    score = 0

    # ── IP reputation (0-40 pts) ────────────────────────────────────────────────
    abuse_score = int(session_data.get("abuse_score", 0))
    score += int(abuse_score * 0.40)

    # ── Anonymization tools (0-10 pts) ─────────────────────────────────────────
    if session_data.get("is_tor") or session_data.get("is_vpn") or session_data.get("is_proxy"):
        score += 10

    # ── Malware detected (0-20 pts) ────────────────────────────────────────────
    yara_matches = session_data.get("yara_matches") or []
    if yara_matches:
        # Extra weight for critical malware families
        high_severity = {"Mirai_Botnet", "WannaCry_Ransomware", "Emotet_Loader"}
        if any(m in high_severity for m in yara_matches):
            score += 20
        else:
            score += 12

    # ── VirusTotal detections (0-15 pts) ───────────────────────────────────────
    vt_malicious = int(session_data.get("vt_malicious", 0))
    if vt_malicious > 10:
        score += 15
    elif vt_malicious > 0:
        score += 8

    # ── Login attempt volume (0-10 pts) ────────────────────────────────────────
    attempts = int(session_data.get("login_attempts", 0))
    if attempts > 500:
        score += 10
    elif attempts > 100:
        score += 5
    elif attempts > 10:
        score += 2

    # ── Critical service targeting (0-5 pts) ───────────────────────────────────
    dest_port = session_data.get("destination_port")
    if dest_port and int(dest_port) in CRITICAL_PORTS:
        score += 5

    # ── Post-exploitation signals (bonus, capped at total 100) ─────────────────
    # Commands executed in shell (Cowrie)
    command_count = int(session_data.get("command_count", 0))
    if command_count > 20:
        score += 5
    elif command_count > 5:
        score += 2

    # Large data transfer
    exfil_bytes = int(session_data.get("exfil_bytes", 0))
    if exfil_bytes > 1_000_000:   # >1MB
        score += 5
    elif exfil_bytes > 100_000:   # >100KB
        score += 2

    return min(score, 100)


def risk_level(score: int) -> str:
    """Human-readable risk level from numeric score."""
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    elif score >= 20:
        return "LOW"
    else:
        return "INFO"
