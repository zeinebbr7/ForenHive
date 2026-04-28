"""
ForenHive Forensic Engine — Risk Score Calculator (full enrichment)

Leverages every available signal from the existing toolchain:
  - AbuseIPDB: confidence + total_reports + isp
  - IPLocate: Tor / VPN / proxy / hosting detection
  - GeoIP (MaxMind): country, ASN, organization
  - Shodan InternetDB: vulns on attacker IP, tags, open ports, hostnames
  - YARA: rule matches on dropped binaries
  - VirusTotal: malicious count + family + tags + names + first_seen
  - Dionaea SMB analyzer: NetShareEnum, epmapper prescan, exploit probes
  - Cowrie: login attempts (split success/failed), commands, exfil bytes
  - Multi-honeypot correlation (Cowrie + Dionaea + Galah + Zeek)
  - Session timestamps → duration, attack velocity, off-hours
  - PostgreSQL history → recidivism (previously-seen attacker)

Output blocks (13 keys):
  score, level, confidence
  signal_breakdown         per-signal points + explanation (for charts)
  attack_types             classified categories (for badges)
  mitre_techniques         deterministic ATT&CK mapping
  lateral_movement         bool flag
  data_quality             availability + warnings
  notes                    terse technical flags
  narrative                human-readable paragraph (for reports)
  recommended_actions      SOC playbook steps
  iocs                     structured indicators for threat intel export
  attribution              attacker fingerprint (geo, ASN, profile)

Private IPs: reputation skipped, behavioral signals ×2.
Docker bridge and loopback IPs are filtered upstream in engine.py.
"""

import math

# ── Critical ports ─────────────────────────────────────────────────────────────
CRITICAL_PORTS = {
    22:    "SSH",
    23:    "Telnet",
    445:   "SMB",
    1433:  "MSSQL",
    3306:  "MySQL",
    5432:  "PostgreSQL",
    6379:  "Redis",
    9200:  "Elasticsearch",
    27017: "MongoDB",
    2375:  "Docker daemon",
}

# ── Signal weights ─────────────────────────────────────────────────────────────
SMB_SHARE_ENUM_SCORE      = 30
EPMAPPER_PRESCAN_SCORE    = 15
EXPLOIT_CVE_SCORE         = 40
MULTI_HONEYPOT_SCORE      = 10
SUCCESS_COMPROMISE_SCORE  = 25   # MASSIVE signal — attacker actually logged in
ATTACKER_COMPROMISED_SCORE = 10  # Shodan vulns on attacker IP (botnet zombie)
HOSTING_SCORE             = 5    # VPS / cloud provider origin
VELOCITY_SCORE            = 5    # automated attack speed
RECIDIVISM_SCORE          = 10   # previously seen attacker
TEMPORAL_SCORE            = 5    # off-hours attack

# Login attempt thresholds
LOGIN_HIGH = 200
LOGIN_MED  = 50
LOGIN_LOW  = 10

# Attack velocity threshold (attempts / second)
VELOCITY_THRESHOLD = 2.0

# High-severity YARA families
_HIGH_SEV_YARA = {"Mirai_Botnet", "WannaCry_Ransomware", "Emotet_Loader",
                  "Cobalt_Strike", "Metasploit_Payload"}

# Known VPS / cloud provider ASN name substrings (uppercased)
_VPS_ASN_PATTERNS = (
    "AMAZON", "AWS", "DIGITALOCEAN", "LINODE", "OVH", "HETZNER",
    "CHOOPA", "VULTR", "LEASEWEB", "CONTABO", "MICROSOFT", "AZURE",
    "GOOGLE", "CLOUDFLARE", "ALIBABA", "TENCENT", "SCALEWAY", "UPCLOUD",
    "ONLINE SAS", "SERVER4YOU", "M247",
)

# Shodan tags that indicate compromised or malicious infrastructure
_SHODAN_BAD_TAGS = {"malware", "c2", "botnet", "tor", "cloud"}

# ── MITRE ATT&CK catalogue (deterministic, signal-driven) ─────────────────────
_MITRE = {
    "brute_force":        {"id": "T1110",     "name": "Brute Force",
                           "tactic": "credential-access"},
    "pass_guessing":      {"id": "T1110.001", "name": "Password Guessing",
                           "tactic": "credential-access"},
    "valid_accounts":     {"id": "T1078",     "name": "Valid Accounts",
                           "tactic": "initial-access"},
    "net_share_disc":     {"id": "T1135",     "name": "Network Share Discovery",
                           "tactic": "discovery"},
    "net_service_scan":   {"id": "T1046",     "name": "Network Service Scanning",
                           "tactic": "discovery"},
    "active_scan":        {"id": "T1595",     "name": "Active Scanning",
                           "tactic": "reconnaissance"},
    "exploit_app":        {"id": "T1190",     "name": "Exploit Public-Facing Application",
                           "tactic": "initial-access"},
    "ingress_tool":       {"id": "T1105",     "name": "Ingress Tool Transfer",
                           "tactic": "command-and-control"},
    "cmd_scripting":      {"id": "T1059",     "name": "Command and Scripting Interpreter",
                           "tactic": "execution"},
    "exfiltration_c2":    {"id": "T1041",     "name": "Exfiltration Over C2 Channel",
                           "tactic": "exfiltration"},
    "proxy_anon":         {"id": "T1090",     "name": "Proxy",
                           "tactic": "command-and-control"},
    "lateral_smb":        {"id": "T1021.002", "name": "Remote Services: SMB/Windows Admin Shares",
                           "tactic": "lateral-movement"},
    "obfuscated_files":   {"id": "T1027",     "name": "Obfuscated Files or Information",
                           "tactic": "defense-evasion"},
    "compromise_infra":   {"id": "T1584",     "name": "Compromise Infrastructure",
                           "tactic": "resource-development"},
    "acquire_infra":      {"id": "T1583",     "name": "Acquire Infrastructure",
                           "tactic": "resource-development"},
}


# ── Helper: detect hosting/VPS from ASN/ISP strings ───────────────────────────

def _is_hosting_asn(geo_org: str, geo_isp: str) -> bool:
    """Return True if ASN org or ISP string matches a known hosting provider."""
    haystack = f"{geo_org} {geo_isp}".upper()
    return any(p in haystack for p in _VPS_ASN_PATTERNS)


# ── Main function ──────────────────────────────────────────────────────────────

def calculate_risk_score(session_data: dict) -> dict:
    """Full forensic assessment — see module docstring for output keys."""

    # ── Extract inputs ────────────────────────────────────────────────────────
    source_ip     = session_data.get("source_ip", "unknown")
    session_id    = session_data.get("session_id", "")
    is_private    = session_data.get("is_private", False)
    vt_available  = session_data.get("vt_available", True)
    network_class = session_data.get("network_class", "external")

    # Reputation
    abuse_score    = int(session_data.get("abuse_score", 0))
    abuse_reports  = int(session_data.get("abuse_total_reports", 0))
    abuse_distinct = int(session_data.get("abuse_distinct_users", 0))
    abuse_last     = session_data.get("abuse_last_reported", "")
    abuse_cats     = list(session_data.get("abuse_categories", []) or [])
    abuse_usage    = session_data.get("abuse_usage_type", "")
    is_tor         = session_data.get("is_tor", False)
    is_vpn         = session_data.get("is_vpn", False)
    is_proxy       = session_data.get("is_proxy", False)
    is_hosting     = session_data.get("is_hosting", False)
    is_datacenter  = session_data.get("is_datacenter", False)
    is_abuser_list = session_data.get("is_abuser_listed", False)
    is_bogon       = session_data.get("is_bogon", False)

    # Geo / ASN
    geo_country      = session_data.get("geo_country", "")
    geo_country_code = session_data.get("geo_country_code", "")
    geo_region       = session_data.get("geo_region", "")
    geo_city         = session_data.get("geo_city", "")
    geo_asn          = session_data.get("geo_asn", 0)
    geo_org          = session_data.get("geo_org", "")
    geo_isp          = session_data.get("geo_isp", "")
    network_cidr     = session_data.get("network_cidr", "")
    ptr_hostname     = session_data.get("ptr_hostname", "")
    all_hostnames    = list(session_data.get("all_hostnames", []) or [])
    abuse_contact    = session_data.get("abuse_contact", "")
    threat_tier      = session_data.get("threat_tier", "")

    # Shodan attacker infrastructure
    shodan_vulns     = list(session_data.get("shodan_vulns", []) or [])
    shodan_tags      = list(session_data.get("shodan_tags", []) or [])
    shodan_ports     = list(session_data.get("shodan_open_ports", []) or [])
    shodan_hostnames = list(session_data.get("shodan_hostnames", []) or [])

    # Malware
    yara_matches  = list(session_data.get("yara_matches") or [])
    vt_malicious  = int(session_data.get("vt_malicious", 0))
    vt_family     = session_data.get("vt_family", "") or ""
    vt_tags       = list(session_data.get("vt_tags", []) or [])
    vt_names      = list(session_data.get("vt_names", []) or [])
    vt_first_seen = session_data.get("vt_first_seen", "") or ""
    sha256_hashes = list(session_data.get("sha256_hashes", []) or [])

    # Activity
    attempts      = int(session_data.get("login_attempts", 0))
    success_count = int(session_data.get("success_count", 0))
    failed_count  = int(session_data.get("failed_count", 0))
    dest_port     = session_data.get("destination_port")
    command_count = int(session_data.get("command_count", 0))
    exfil_bytes   = int(session_data.get("exfil_bytes", 0))

    # SMB
    smb_share_enum = bool(session_data.get("smb_share_enum", False))
    epmapper_count = int(session_data.get("epmapper_prescan", 0) or 0)
    exploit_cve    = list(session_data.get("exploit_cve") or [])

    # Correlation
    honeypot_types = sorted(set(session_data.get("honeypot_types_hit") or []))

    # Time / recidivism
    duration_sec      = float(session_data.get("session_duration_sec", 0) or 0)
    velocity          = float(session_data.get("attack_velocity", 0) or 0)
    is_off_hours      = bool(session_data.get("is_off_hours", False))
    hour_local        = int(session_data.get("hour_local", -1))
    previously_seen   = bool(session_data.get("previously_seen", False))
    previous_sessions = int(session_data.get("previous_sessions", 0))

    # Behavioral weight (×2 for private IPs)
    w = 2 if is_private else 1

    # ── Initialize accumulators ───────────────────────────────────────────────
    score        = 0
    notes        = []
    breakdown    = {}
    techniques   = []
    attack_types = set()

    # ── 1. IP reputation confidence (external only, 0-40 pts) ────────────────
    if not is_private:
        rep_pts = int(abuse_score * 0.40)
        score += rep_pts
        breakdown["reputation"] = {
            "points": rep_pts, "max": 40,
            "detail": f"AbuseIPDB confidence {abuse_score}/100 → {rep_pts} pts",
            "available": abuse_score > 0,
        }
    else:
        breakdown["reputation"] = {
            "points": 0, "max": 40,
            "detail": f"private IP ({network_class}) — AbuseIPDB not applicable",
            "available": False,
        }
        notes.append(f"private_ip:{network_class} — reputation skipped, behavioral weight ×2")

    # ── 2. IP reputation volume (external only, 0-10 pts, log scale) ─────────
    # 1 report = 0, 10 = 3, 100 = 6, 1000+ = 10
    vol_pts = 0
    if not is_private and abuse_reports > 0:
        vol_pts = min(int(math.log10(max(abuse_reports, 1)) * 3.3), 10)
        score += vol_pts
    breakdown["reputation_volume"] = {
        "points": vol_pts, "max": 10,
        "detail": f"AbuseIPDB reported {abuse_reports} time(s)" if not is_private
                  else "private IP — report volume not applicable",
        "available": (not is_private) and abuse_reports > 0,
    }

    # ── 3. Anonymization (external only, 0-10 pts) ───────────────────────────
    anon_pts = 0
    anon_flags = []
    if not is_private:
        if is_tor:
            anon_pts = 10; anon_flags.append("Tor")
        elif is_vpn:
            anon_pts = 10; anon_flags.append("VPN")
        elif is_proxy:
            anon_pts = 10; anon_flags.append("proxy")
        score += anon_pts
        if anon_pts:
            techniques.append("proxy_anon")
            attack_types.add("anonymized_attacker")
        if is_bogon:
            notes.append("bogon_ip:source IP is in unallocated/reserved space (spoofed?)")
        if is_abuser_list:
            notes.append("iplocate_abuser_listed:IP flagged as abuser by IPLocate")
    breakdown["anonymization"] = {
        "points": anon_pts, "max": 10,
        "detail": f"anonymization: {', '.join(anon_flags)}" if anon_flags
                  else ("no anonymization detected" if not is_private
                        else "private IP — not applicable"),
        "available": not is_private,
    }

    # ── 4. Attacker infrastructure (Shodan, 0-15 pts) ────────────────────────
    infra_pts = 0
    infra_details = []
    attacker_compromised = False
    attacker_is_hosting  = False

    if shodan_vulns:
        infra_pts += ATTACKER_COMPROMISED_SCORE
        attacker_compromised = True
        infra_details.append(f"{len(shodan_vulns)} known vulns on attacker IP (likely compromised zombie)")
        techniques.append("compromise_infra")
        attack_types.add("compromised_host")

    bad_tags = [t for t in shodan_tags if t.lower() in _SHODAN_BAD_TAGS]
    if bad_tags:
        infra_details.append(f"Shodan tags: {bad_tags}")

    if is_hosting or is_datacenter or _is_hosting_asn(geo_org, geo_isp):
        infra_pts += HOSTING_SCORE
        attacker_is_hosting = True
        src = geo_org or geo_isp or "VPS"
        if is_datacenter:
            infra_details.append(f"datacenter/hosting ({src}) — IPLocate confirmed")
        else:
            infra_details.append(f"hosted infrastructure ({src})")
        techniques.append("acquire_infra")

    # AbuseIPDB report categories enrich attack_types automatically
    # (cat 18=Brute-Force, 22=SSH, 14=Port Scan, 21=Web App, 16=SQLi, 15=Hacking, 4=DDoS)
    cat_to_type = {
        "Brute-Force": "brute_force", "SSH": "brute_force",
        "FTP Brute-Force": "brute_force", "Port Scan": "reconnaissance",
        "Web App Attack": "exploitation", "SQL Injection": "exploitation",
        "Hacking": "exploitation", "DDoS Attack": "ddos",
        "Phishing": "phishing", "Web Spam": "spam", "Email Spam": "spam",
        "Bad Web Bot": "automated", "Exploited Host": "compromised_host",
    }
    for label in abuse_cats:
        t = cat_to_type.get(label)
        if t:
            attack_types.add(t)

    if infra_pts > 0:
        score += infra_pts
    breakdown["attacker_infrastructure"] = {
        "points": infra_pts, "max": 15,
        "detail": "; ".join(infra_details) if infra_details
                  else "no attacker-infrastructure red flags",
        "available": not is_private,
    }

    # ── 5. YARA malware detection (0-45 pts with weight) ─────────────────────
    yara_pts = 0
    if yara_matches:
        high_sev = [m for m in yara_matches if m in _HIGH_SEV_YARA]
        base = 20 if high_sev else 12
        yara_pts = base * w
        if not vt_available:
            yara_pts += 5
            notes.append("vt_unavailable:yara_score_includes_uncertainty_bonus")
        score += yara_pts
        techniques.append("ingress_tool")
        if high_sev:
            techniques.append("obfuscated_files")
        attack_types.add("malware_delivery")
        detail = f"YARA rules matched: {', '.join(yara_matches)}"
        if w == 2:
            detail += " (×2 weight, private IP)"
    else:
        detail = "no YARA matches"
    breakdown["malware_yara"] = {
        "points": yara_pts, "max": 45,
        "detail": detail,
        "available": True,
    }

    # ── 6. VirusTotal detections (0-15 pts) — enriched with family/tags ──────
    vt_pts = 0
    if vt_available:
        if vt_malicious > 10:
            vt_pts = 15
            vt_detail = f"{vt_malicious} AV engines flagged"
        elif vt_malicious > 0:
            vt_pts = 8
            vt_detail = f"{vt_malicious} AV engine(s) flagged"
        else:
            vt_detail = "clean or unknown on VirusTotal"
        score += vt_pts
        if vt_family:
            vt_detail += f" — family: {vt_family}"
        if vt_tags:
            vt_detail += f" — tags: {vt_tags[:4]}"
        if vt_pts:
            attack_types.add("malware_delivery")
    else:
        vt_detail = "VirusTotal quota exhausted — result unavailable"
        notes.append("vt_quota_exhausted:vt_signal_unavailable")
    breakdown["malware_vt"] = {
        "points": vt_pts, "max": 15,
        "detail": vt_detail,
        "available": vt_available,
    }

    # ── 7. Login attempt volume (0-20 pts with weight) ────────────────────────
    login_pts = 0
    if attempts > LOGIN_HIGH:
        login_pts = 10 * w
        login_detail = f"{attempts} attempts (>{LOGIN_HIGH} high-volume brute force)"
        techniques.append("pass_guessing")
    elif attempts > LOGIN_MED:
        login_pts = 5 * w
        login_detail = f"{attempts} attempts (>{LOGIN_MED} credential spray)"
        techniques.append("brute_force")
    elif attempts > LOGIN_LOW:
        login_pts = 2 * w
        login_detail = f"{attempts} attempts (>{LOGIN_LOW} low-volume probe)"
        techniques.append("brute_force")
    else:
        login_detail = f"{attempts} login attempt(s) — below threshold"
    if login_pts:
        score += login_pts
        attack_types.add("brute_force")
        if w == 2:
            login_detail += " (×2 weight, private IP)"
    breakdown["login_volume"] = {
        "points": login_pts, "max": 20,
        "detail": login_detail,
        "available": True,
    }

    # ── 8. Successful compromise (+25 pts) ────────────────────────────────────
    compromise_pts = 0
    if success_count > 0:
        compromise_pts = SUCCESS_COMPROMISE_SCORE
        score += compromise_pts
        techniques.append("valid_accounts")
        attack_types.add("credential_compromise")
        notes.append(f"successful_login:{success_count} auth(s) — T1078 Valid Accounts")
    breakdown["successful_compromise"] = {
        "points": compromise_pts, "max": SUCCESS_COMPROMISE_SCORE,
        "detail": f"{success_count} successful login(s) out of {attempts} attempts"
                  if success_count else "no successful authentications",
        "available": True,
    }

    # ── 9. Critical service targeting (0-5 pts) ───────────────────────────────
    port_pts  = 0
    port_name = ""
    if dest_port:
        try:
            port_name = CRITICAL_PORTS.get(int(dest_port), "")
        except (ValueError, TypeError):
            port_name = ""
        if port_name:
            port_pts = 5
            score += port_pts
            attack_types.add("critical_service_targeting")
            if int(dest_port) not in (22, 23):
                techniques.append("exploit_app")
    breakdown["critical_port"] = {
        "points": port_pts, "max": 5,
        "detail": f"port {dest_port} ({port_name})" if port_name else
                  f"port {dest_port} (non-critical)" if dest_port else "no destination port",
        "available": dest_port is not None,
    }

    # ── 10. Post-exploitation — command execution (0-10 pts) ─────────────────
    cmd_pts = 0
    if command_count > 20:
        cmd_pts = 5 * w
        cmd_detail = f"{command_count} commands executed (active post-exploitation)"
        techniques.append("cmd_scripting")
        attack_types.add("post_exploitation")
    elif command_count > 5:
        cmd_pts = 2 * w
        cmd_detail = f"{command_count} commands executed (interactive session)"
        techniques.append("cmd_scripting")
        attack_types.add("post_exploitation")
    else:
        cmd_detail = f"{command_count} command(s) — below threshold"
    if cmd_pts:
        score += cmd_pts
        if w == 2:
            cmd_detail += " (×2 weight, private IP)"
    breakdown["commands"] = {
        "points": cmd_pts, "max": 10,
        "detail": cmd_detail, "available": True,
    }

    # ── 11. Post-exploitation — data exfiltration (0-10 pts) ─────────────────
    exfil_pts = 0
    if exfil_bytes > 1_000_000:
        exfil_pts = 5 * w
        exfil_detail = f"{exfil_bytes / 1_000_000:.1f} MB transferred (likely exfiltration)"
        techniques.append("exfiltration_c2")
        attack_types.add("post_exploitation")
    elif exfil_bytes > 100_000:
        exfil_pts = 2 * w
        exfil_detail = f"{exfil_bytes / 1_000:.0f} KB transferred (suspicious volume)"
        attack_types.add("post_exploitation")
    else:
        exfil_detail = f"{exfil_bytes} bytes transferred — normal range"
    if exfil_pts:
        score += exfil_pts
        if w == 2:
            exfil_detail += " (×2 weight, private IP)"
    breakdown["exfiltration"] = {
        "points": exfil_pts, "max": 10,
        "detail": exfil_detail, "available": True,
    }

    # ── 12. Attack velocity (0-5 pts) ────────────────────────────────────────
    vel_pts = 0
    if velocity >= VELOCITY_THRESHOLD and attempts >= LOGIN_LOW:
        vel_pts = VELOCITY_SCORE
        score += vel_pts
        attack_types.add("automated")
        vel_detail = f"{velocity:.1f} attempts/sec over {duration_sec:.0f}s (automated tooling)"
    else:
        vel_detail = (f"{velocity:.2f} attempts/sec" if duration_sec > 0
                      else "insufficient data")
    breakdown["attack_velocity"] = {
        "points": vel_pts, "max": VELOCITY_SCORE,
        "detail": vel_detail,
        "available": duration_sec > 0,
    }

    # ── 13. SMB NetShareEnum (+30 pts) ────────────────────────────────────────
    smb_enum_pts = 0
    if smb_share_enum:
        smb_enum_pts = SMB_SHARE_ENUM_SCORE
        score += smb_enum_pts
        techniques += ["net_share_disc", "lateral_smb"]
        attack_types.add("reconnaissance")
        attack_types.add("lateral_movement")
        notes.append("smb:NetShareEnum (T1135) detected")
    breakdown["smb_share_enum"] = {
        "points": smb_enum_pts, "max": SMB_SHARE_ENUM_SCORE,
        "detail": "NetShareEnum (SRVSVC opnum 15) observed" if smb_enum_pts
                  else "no SMB share enumeration",
        "available": True,
    }

    # ── 14. SMB epmapper pre-scan (+15 pts) ──────────────────────────────────
    epm_pts = 0
    if epmapper_count > 0:
        epm_pts = EPMAPPER_PRESCAN_SCORE
        score += epm_pts
        techniques.append("net_service_scan")
        attack_types.add("reconnaissance")
        notes.append(f"smb:epmapper_prescan ({epmapper_count} queries, T1046)")
    breakdown["smb_epmapper"] = {
        "points": epm_pts, "max": EPMAPPER_PRESCAN_SCORE,
        "detail": f"epmapper pre-scan ({epmapper_count} DCE/RPC queries)" if epm_pts
                  else "no epmapper scanning",
        "available": True,
    }

    # ── 15. Exploit CVE probes (+40 pts) ─────────────────────────────────────
    exp_pts = 0
    if exploit_cve:
        exp_pts = EXPLOIT_CVE_SCORE
        score += exp_pts
        techniques.append("exploit_app")
        attack_types.add("exploitation")
        notes.append(f"exploit_probe:{exploit_cve} (T1190)")
    breakdown["exploit_cve"] = {
        "points": exp_pts, "max": EXPLOIT_CVE_SCORE,
        "detail": f"CVE probes: {', '.join(exploit_cve)}" if exp_pts
                  else "no known exploit probes",
        "available": True,
    }

    # ── 16. Multi-honeypot correlation (+10 pts) ──────────────────────────────
    multi_pts = 0
    if len(honeypot_types) > 1:
        multi_pts = MULTI_HONEYPOT_SCORE
        score += multi_pts
        techniques.append("active_scan")
        attack_types.add("reconnaissance")
        notes.append(f"multi_honeypot:{honeypot_types} (T1595)")
    breakdown["multi_honeypot"] = {
        "points": multi_pts, "max": MULTI_HONEYPOT_SCORE,
        "detail": f"hit {len(honeypot_types)} honeypot types: {honeypot_types}"
                  if multi_pts else
                  f"single honeypot: {honeypot_types[0] if honeypot_types else 'unknown'}",
        "available": True,
    }

    # ── 17. Recidivism — previously seen attacker (+10 pts) ──────────────────
    recid_pts = 0
    if previously_seen:
        recid_pts = RECIDIVISM_SCORE
        score += recid_pts
        attack_types.add("persistent_attacker")
        notes.append(f"recidivism:{previous_sessions}_prior_sessions")
    breakdown["recidivism"] = {
        "points": recid_pts, "max": RECIDIVISM_SCORE,
        "detail": f"previously seen in {previous_sessions} prior session(s)"
                  if previously_seen else "first time seen on this platform",
        "available": True,
    }

    # ── 18. Temporal anomaly — off-hours attack (+5 pts) ─────────────────────
    temporal_pts = 0
    if is_off_hours:
        temporal_pts = TEMPORAL_SCORE
        score += temporal_pts
        attack_types.add("off_hours")
    breakdown["temporal_anomaly"] = {
        "points": temporal_pts, "max": TEMPORAL_SCORE,
        "detail": f"session started at {hour_local:02d}:00 local time (off-hours)"
                  if temporal_pts else
                  (f"session started at {hour_local:02d}:00 local time"
                   if hour_local >= 0 else "no timestamp available"),
        "available": hour_local >= 0,
    }

    # ── Finalize ──────────────────────────────────────────────────────────────
    final_score = min(score, 100)
    level       = risk_level(final_score)
    lateral     = is_private and final_score >= 50

    # ── Confidence ────────────────────────────────────────────────────────────
    active_signals = sum(1 for v in breakdown.values() if v["points"] > 0)
    has_reputation = (not is_private) and abuse_score > 0

    if not vt_available and not yara_matches and not exploit_cve:
        confidence = "LOW"
    elif active_signals >= 4 and (vt_available or exploit_cve or yara_matches or success_count):
        confidence = "HIGH"
    elif active_signals >= 2 or exploit_cve or (yara_matches and vt_available) or success_count:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    # ── MITRE deduplication ───────────────────────────────────────────────────
    seen_ids = set()
    mitre_out = []
    for key in techniques:
        t = _MITRE.get(key)
        if t and t["id"] not in seen_ids:
            mitre_out.append(dict(t))
            seen_ids.add(t["id"])

    # ── Data quality ──────────────────────────────────────────────────────────
    dq_warnings = []
    if not vt_available:
        dq_warnings.append("VirusTotal quota exhausted — malware verdict may be incomplete")
    if is_private:
        dq_warnings.append(f"Private IP ({network_class}) — AbuseIPDB/GeoIP/IPLocate not applicable")
    if not is_private and not has_reputation:
        dq_warnings.append("AbuseIPDB returned no data — IP may be unlisted or key missing")
    if not honeypot_types:
        dq_warnings.append("No honeypot-type correlation data")
    if duration_sec == 0:
        dq_warnings.append("No session duration — velocity and off-hours checks unavailable")

    data_quality = {
        "vt_available":         vt_available,
        "reputation_available": has_reputation,
        "smb_data_available":   bool(smb_share_enum or epmapper_count),
        "multi_honeypot_data":  bool(honeypot_types),
        "shodan_data":          bool(shodan_vulns or shodan_tags or shodan_ports),
        "geo_data":             bool(geo_country_code),
        "timing_data":          duration_sec > 0,
        "warnings":             dq_warnings,
    }

    # ── Attribution (attacker fingerprint) ────────────────────────────────────
    attacker_profile = _classify_attacker_profile(
        is_private, network_class, is_tor, is_vpn, is_proxy,
        attacker_is_hosting, attacker_compromised,
    )
    attribution = {
        "source_ip":             source_ip,
        "country":               geo_country or "unknown",
        "country_code":          geo_country_code or "",
        "region":                geo_region,
        "city":                  geo_city,
        "asn":                   geo_asn,
        "asn_org":               geo_org,
        "isp":                   geo_isp,
        "network_cidr":          network_cidr,
        "ptr_hostname":          ptr_hostname,
        "hostnames":             sorted(set(shodan_hostnames + all_hostnames)),
        "abuse_contact":         abuse_contact,
        "abuse_usage_type":      abuse_usage,
        "abuse_categories":      abuse_cats,
        "abuse_distinct_reporters": abuse_distinct,
        "abuse_last_reported":   abuse_last,
        "is_hosting":            attacker_is_hosting,
        "is_datacenter":         is_datacenter,
        "is_bogon":              is_bogon,
        "is_abuser_listed":      is_abuser_list,
        "likely_compromised":    attacker_compromised,
        "anonymization":         anon_flags,
        "attacker_profile":      attacker_profile,
        "threat_tier":           threat_tier,
        "previously_seen":       previously_seen,
        "previous_session_count": previous_sessions,
    }

    # ── IOCs (exportable to threat intel) ─────────────────────────────────────
    iocs = {
        "source_ip":     source_ip,
        "session_id":    session_id,
        "asn":           geo_asn,
        "asn_org":       geo_org,
        "country_code":  geo_country_code,
        "city":          geo_city,
        "network_cidr":  network_cidr,
        "ptr_hostname":  ptr_hostname,
        "sha256_hashes": sha256_hashes,
        "yara_families": yara_matches,
        "vt_families":   [vt_family] if vt_family else [],
        "vt_tags":       vt_tags,
        "vt_file_names": vt_names[:5],
        "cves_probed":   exploit_cve,
        "ports_targeted": [dest_port] if dest_port else [],
        "hostnames":     sorted(set(shodan_hostnames + all_hostnames)),
        "abuse_categories": abuse_cats,
        "abuse_contact": abuse_contact,
    }

    # ── Narrative (for reports) ───────────────────────────────────────────────
    narrative = _build_narrative(
        source_ip, is_private, network_class, geo_country, geo_org, attribution,
        honeypot_types, attempts, success_count, dest_port, port_name,
        yara_matches, vt_malicious, vt_available, vt_family, vt_tags,
        exploit_cve, epmapper_count, smb_share_enum,
        command_count, exfil_bytes, velocity, duration_sec, is_off_hours,
        hour_local, previously_seen, previous_sessions, attacker_compromised,
        lateral, confidence, final_score, level,
    )

    # ── Recommendations (SOC playbook) ───────────────────────────────────────
    actions = _build_recommendations(
        source_ip, final_score, level, lateral, set(attack_types),
        exploit_cve, yara_matches, vt_available, is_private,
        success_count, attacker_compromised,
    )

    return {
        "score":               final_score,
        "level":               level,
        "confidence":          confidence,
        "signal_breakdown":    breakdown,
        "attack_types":        sorted(attack_types),
        "mitre_techniques":    mitre_out,
        "lateral_movement":    lateral,
        "data_quality":        data_quality,
        "notes":               notes,
        "narrative":           narrative,
        "recommended_actions": actions,
        "iocs":                iocs,
        "attribution":         attribution,
    }


# ── Attacker profile classifier ────────────────────────────────────────────────

def _classify_attacker_profile(is_private, network_class, is_tor, is_vpn, is_proxy,
                               is_hosting, is_compromised):
    if is_private:
        return f"internal_{network_class}"
    if is_tor:
        return "tor_exit_node"
    if is_compromised:
        return "compromised_host_botnet_zombie"
    if is_hosting:
        return "hosting_provider_vps"
    if is_vpn or is_proxy:
        return "commercial_anonymization"
    return "residential_or_unknown"


# ── Narrative builder ──────────────────────────────────────────────────────────

def _build_narrative(
    ip, is_private, network_class, country, org, attribution,
    honeypot_types, attempts, success_count, dest_port, port_name,
    yara_matches, vt_malicious, vt_available, vt_family, vt_tags,
    exploit_cve, epmapper_count, smb_share_enum,
    command_count, exfil_bytes, velocity, duration_sec, is_off_hours,
    hour_local, previously_seen, previous_sessions, attacker_compromised,
    lateral, confidence, score, level,
) -> str:
    parts = []

    # ── Subject ──
    if is_private:
        subject = f"Internal host {ip} ({network_class.replace('_', ' ')})"
    else:
        geo_frag = ""
        if country and country != "unknown":
            city = attribution.get("city") or ""
            geo_frag = f" (origin: {city + ', ' if city else ''}{country}"
            if org:
                geo_frag += f", {org}"
            cidr = attribution.get("network_cidr") or ""
            if cidr:
                geo_frag += f", CIDR {cidr}"
            geo_frag += ")"
        ptr = attribution.get("ptr_hostname") or ""
        if ptr:
            geo_frag += f" PTR={ptr}"
        profile = attribution.get("attacker_profile", "")
        profile_frag = ""
        if profile and profile not in ("residential_or_unknown",):
            profile_frag = f" [{profile.replace('_', ' ')}]"
        subject = f"External host {ip}{geo_frag}{profile_frag}"

    # ── Honeypot context ──
    if len(honeypot_types) > 1:
        hp_str = f"across {len(honeypot_types)} honeypot types ({', '.join(honeypot_types)})"
    elif honeypot_types:
        hp_str = f"against the {honeypot_types[0]} honeypot"
    else:
        hp_str = "against the honeypot infrastructure"

    parts.append(f"{subject} was observed performing malicious activity {hp_str}.")

    # ── AbuseIPDB historical context ──
    cats = attribution.get("abuse_categories") or []
    distinct = attribution.get("abuse_distinct_reporters") or 0
    if cats or distinct:
        cat_str = f" — categories: {', '.join(cats[:5])}" if cats else ""
        rep_str = f" reported by {distinct} distinct reporters" if distinct else ""
        parts.append(f"AbuseIPDB shows prior malicious activity{rep_str}{cat_str}.")

    # ── Recidivism ──
    if previously_seen:
        parts.append(
            f"This IP is a known persistent attacker — "
            f"previously seen in {previous_sessions} scored session(s)."
        )

    # ── Authentication outcome (most important) ──
    if success_count > 0:
        svc = f" on port {dest_port} ({port_name})" if port_name else ""
        parts.append(
            f"CRITICAL: {success_count} SUCCESSFUL authentication(s){svc} "
            f"out of {attempts} attempts — credentials were compromised (T1078)."
        )
    elif attempts > LOGIN_HIGH:
        svc = f" on port {dest_port} ({port_name})" if port_name else ""
        parts.append(f"It launched a high-volume brute-force attack with {attempts} login attempts{svc}.")
    elif attempts > LOGIN_MED:
        parts.append(f"It performed a credential spray with {attempts} login attempts.")
    elif attempts > LOGIN_LOW:
        parts.append(f"It probed authentication with {attempts} login attempts.")

    # ── Velocity ──
    if velocity >= VELOCITY_THRESHOLD and attempts >= LOGIN_LOW:
        parts.append(
            f"Attack velocity was {velocity:.1f} attempts/second over "
            f"{duration_sec:.0f} seconds, indicating automated tooling."
        )

    # ── SMB ──
    smb_parts = []
    if smb_share_enum:
        smb_parts.append("network share enumeration (NetShareEnum/T1135)")
    if epmapper_count > 0:
        smb_parts.append(f"DCE/RPC epmapper pre-scanning ({epmapper_count} queries/T1046)")
    if smb_parts:
        parts.append(f"SMB activity included {' and '.join(smb_parts)}.")

    # ── Exploitation ──
    if exploit_cve:
        parts.append(f"Known vulnerability probes were detected: {', '.join(exploit_cve)} (T1190).")

    # ── Malware ──
    if yara_matches:
        families = ', '.join(yara_matches)
        malware_desc = f"Dropped files matched YARA rules ({families})"
        if vt_family:
            malware_desc += f", identified as the {vt_family} family"
        if vt_tags:
            malware_desc += f" (VT tags: {', '.join(vt_tags[:3])})"
        if vt_available and vt_malicious > 0:
            malware_desc += f", flagged by {vt_malicious} AV engine(s)."
        elif not vt_available:
            malware_desc += ". VirusTotal confirmation is unavailable (quota exhausted)."
        else:
            malware_desc += " but appeared clean on VirusTotal."
        parts.append(malware_desc)

    # ── Post-exploitation ──
    if command_count > 5:
        parts.append(f"Interactive post-exploitation was observed with {command_count} commands executed.")
    if exfil_bytes > 100_000:
        mb = exfil_bytes / 1_000_000
        parts.append(f"A data transfer of {mb:.2f} MB was recorded, suggesting exfiltration.")

    # ── Attacker infrastructure ──
    if attacker_compromised:
        parts.append(
            "Shodan reports known CVEs on the attacker's own IP — "
            "this host is likely a compromised zombie participating in a botnet."
        )

    # ── Temporal ──
    if is_off_hours and hour_local >= 0:
        parts.append(f"The session occurred during off-hours ({hour_local:02d}:00 defender local time).")

    # ── Lateral movement ──
    if lateral:
        parts.append(
            "Given the private IP origin and high behavioral score, "
            "lateral movement or insider threat activity is strongly suspected."
        )

    # ── Confidence ──
    conf_phrase = {
        "HIGH":   "Evidence is strong and corroborated by multiple independent signals.",
        "MEDIUM": "Evidence is moderate; some signals may be incomplete.",
        "LOW":    "Evidence is limited; score may change when full signal data is available.",
    }[confidence]
    parts.append(conf_phrase)

    parts.append(f"Overall risk assessment: {level} ({score}/100).")

    return " ".join(parts)


# ── Recommendation builder ─────────────────────────────────────────────────────

def _build_recommendations(
    ip, score, level, lateral, attack_types,
    exploit_cve, yara_matches, vt_available, is_private,
    success_count, attacker_compromised,
) -> list:
    actions = []

    # ── Credential compromise — HIGHEST PRIORITY ──
    if success_count > 0:
        actions.append(
            f"CRITICAL: {success_count} successful authentication(s) detected. "
            f"Immediately rotate any credentials that may have been used on the honeypot. "
            f"Audit all systems where those credentials are valid."
        )

    # ── Triage by level ──
    if level == "CRITICAL":
        actions.append("IMMEDIATE: Escalate to incident response team — risk level is CRITICAL.")
        if is_private:
            actions.append(f"IMMEDIATE: Isolate host {ip} from the network pending investigation.")
        else:
            actions.append(f"IMMEDIATE: Block {ip} at perimeter firewall and WAF.")
    elif level == "HIGH":
        if is_private:
            actions.append(f"Investigate host {ip} as a priority — high-risk internal activity detected.")
        else:
            actions.append(f"Block {ip} at firewall and add to threat intelligence blocklist.")
    elif level == "MEDIUM":
        actions.append(f"Monitor {ip} for escalation; consider adding to watchlist.")
    else:
        actions.append(f"Log and observe {ip}; no immediate action required.")

    # ── Attack-type-specific ──
    if "brute_force" in attack_types:
        actions.append(
            f"Audit all authentication logs for {ip} — check for any successful logins "
            f"that may have occurred before detection."
        )

    if "lateral_movement" in attack_types or lateral:
        actions.append(
            f"Review all SMB connections originating from {ip}. "
            f"Check for unauthorized access to network shares and credential relay attacks."
        )
        actions.append(
            "Audit Active Directory for abnormal privilege changes or new service accounts "
            "created around the time of this session."
        )

    if "exploitation" in attack_types and exploit_cve:
        cve_str = ', '.join(exploit_cve)
        actions.append(
            f"Verify patch status for {cve_str} on all systems reachable from {ip}. "
            f"Scan for indicators of compromise if exploit succeeded."
        )

    if "malware_delivery" in attack_types:
        if yara_matches:
            actions.append(
                f"Quarantine all files from this session and submit to sandboxed analysis. "
                f"YARA families matched: {', '.join(yara_matches)}."
            )
        if not vt_available:
            actions.append("Re-run VirusTotal lookups when quota resets — current verdict is incomplete.")

    if "post_exploitation" in attack_types:
        actions.append(
            "Review executed commands in Cowrie session logs for persistence mechanisms, "
            "C2 beaconing, or credential harvesting."
        )

    if "reconnaissance" in attack_types:
        actions.append(
            "Check for follow-up attacks — reconnaissance often precedes exploitation. "
            "Correlate this IP across all honeypot logs."
        )

    if "anonymized_attacker" in attack_types:
        actions.append(
            "Flag as anonymized attacker in threat intelligence. "
            "Correlate with other sessions using the same Tor exit node / VPN range."
        )

    if "automated" in attack_types:
        actions.append(
            "Attack used automated tooling — signatures may match known scanners. "
            "Check rate-limiting and WAF bot-detection rules."
        )

    if "persistent_attacker" in attack_types:
        actions.append(
            f"This attacker has targeted our platform before. "
            f"Review historical sessions for {ip} and correlate TTPs."
        )

    if "compromised_host" in attack_types or attacker_compromised:
        actions.append(
            f"The attacker IP is likely a compromised zombie (vulnerable services exposed). "
            f"Consider coordinated disclosure to the network owner via AbuseIPDB."
        )

    # ── Chain of custody (always) ──
    actions.append(
        "Preserve all raw logs (Cowrie session, Zeek NTLM, Dionaea SQLite) "
        "for chain-of-custody and legal evidence (RFC 3161 timestamping)."
    )

    return actions


# ── Standalone helpers ─────────────────────────────────────────────────────────

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
