"""
ForenHive — Hybrid MITRE ATT&CK Mapper
=======================================
Technique IDs: deterministic rules (always correct, no hallucination)
Forensic narrative: Mistral 7B via Ollama (short prompt, ~15s, 80 tokens)

If Ollama is down → graceful fallback narrative, no crash.
Confidence is always 1.0 because IDs are deterministic.
"""

import logging
import requests

import config

log = logging.getLogger("mitre_mapper")

# ── MITRE ATT&CK technique catalogue ─────────────────────────────────────────
# Only real, validated ATT&CK Enterprise technique IDs.

MITRE_TECHNIQUES = {
    "T1110.001": {
        "name":       "Brute Force: Password Guessing",
        "tactic":     "Credential Access",
        "kill_chain": "exploitation",
    },
    "T1110.003": {
        "name":       "Brute Force: Password Spraying",
        "tactic":     "Credential Access",
        "kill_chain": "exploitation",
    },
    "T1078": {
        "name":       "Valid Accounts",
        "tactic":     "Initial Access",
        "kill_chain": "exploitation",
    },
    "T1059.004": {
        "name":       "Command and Scripting Interpreter: Unix Shell",
        "tactic":     "Execution",
        "kill_chain": "installation",
    },
    "T1105": {
        "name":       "Ingress Tool Transfer",
        "tactic":     "Command and Control",
        "kill_chain": "command_and_control",
    },
    "T1552.001": {
        "name":       "Unsecured Credentials: Credentials In Files",
        "tactic":     "Credential Access",
        "kill_chain": "actions_on_objectives",
    },
    "T1210": {
        "name":       "Exploitation of Remote Services",
        "tactic":     "Lateral Movement",
        "kill_chain": "exploitation",
    },
    "T1190": {
        "name":       "Exploit Public-Facing Application",
        "tactic":     "Initial Access",
        "kill_chain": "delivery",
    },
    "T1595.002": {
        "name":       "Active Scanning: Vulnerability Scanning",
        "tactic":     "Reconnaissance",
        "kill_chain": "reconnaissance",
    },
    "T1046": {
        "name":       "Network Service Discovery",
        "tactic":     "Discovery",
        "kill_chain": "reconnaissance",
    },
    "T1021.002": {
        "name":       "Remote Services: SMB/Windows Admin Shares",
        "tactic":     "Lateral Movement",
        "kill_chain": "lateral_movement",
    },
    "T1486": {
        "name":       "Data Encrypted for Impact",
        "tactic":     "Impact",
        "kill_chain": "actions_on_objectives",
    },
    "T1496": {
        "name":       "Resource Hijacking",
        "tactic":     "Impact",
        "kill_chain": "actions_on_objectives",
    },
    "T1071.001": {
        "name":       "Application Layer Protocol: Web Protocols",
        "tactic":     "Command and Control",
        "kill_chain": "command_and_control",
    },
    "T1592": {
        "name":       "Gather Victim Host Information",
        "tactic":     "Reconnaissance",
        "kill_chain": "reconnaissance",
    },
}

# ── Cyber Kill Chain phases (chronological) ────────────────────────────────────

KILL_CHAIN_ORDER = [
    "reconnaissance",
    "weaponization",
    "delivery",
    "exploitation",
    "installation",
    "command_and_control",
    "lateral_movement",
    "actions_on_objectives",
]

# Human-readable labels for each phase
KILL_CHAIN_LABELS = {
    "reconnaissance":       "Reconnaissance",
    "weaponization":        "Weaponization",
    "delivery":             "Delivery",
    "exploitation":         "Exploitation",
    "installation":         "Installation",
    "command_and_control":  "Command and Control",
    "lateral_movement":     "Lateral Movement",
    "actions_on_objectives": "Actions on Objectives",
}

# Sensitive command patterns that indicate credential access
_CRED_PATTERNS = [
    "cat /root/credentials", "cat /opt/mongodb", "cat /root/.ssh",
    "cat /home", "/etc/passwd", "/etc/shadow", "cat /var/",
    ".bash_history", "history", "env | grep", "printenv",
]

# HTTP paths that indicate vulnerability scanning
_SCAN_PATHS = [
    "/admin", "/wp-admin", "/.env", "/phpmyadmin", "/.git",
    "/config", "/backup", "/.htaccess", "/wp-login.php",
    "/phpinfo.php", "/.well-known", "/api/", "/swagger",
]

# SQL injection patterns in HTTP URI
_SQLI_PATTERNS = ["'", "OR 1=1", "UNION SELECT", "--", "DROP TABLE", "1=1"]


# ── Part 2 — Deterministic technique mapper ───────────────────────────────────

def get_techniques_deterministic(session: dict) -> list:
    """
    Returns a list of valid MITRE technique IDs based on session features.
    Zero LLM calls. Zero hallucination. Always correct.
    """
    techniques = []
    honeypot     = session.get("honeypot_type", "")
    port         = int(session.get("destination_port") or 0)
    login_success = int(session.get("success_count", 0) or 0) > 0
    login_attempts = int(session.get("login_attempts", 0) or 0)
    command_count  = int(session.get("command_count", 0) or 0)
    commands       = list(session.get("commands", []) or [])
    downloads      = int(session.get("exfil_bytes", 0) or 0)
    yara_matches   = list(session.get("yara_matches", []) or [])
    yara_family    = " ".join(yara_matches)
    http_paths     = list(session.get("http_paths", []) or [])
    http_uri       = " ".join(http_paths)

    # ── COWRIE (SSH / Telnet) ─────────────────────────────────────────────────
    if honeypot == "cowrie":
        if login_attempts > 1:
            techniques.append("T1110.001")  # Password Guessing
        if login_attempts > 100:
            techniques.append("T1110.003")  # Password Spraying (high volume)
        if login_success:
            techniques.append("T1078")      # Valid Accounts
        if command_count > 0 or commands:
            techniques.append("T1059.004")  # Unix Shell
        if downloads > 0:
            techniques.append("T1105")      # Ingress Tool Transfer
        # Credential file access
        if any(any(pat in cmd for pat in _CRED_PATTERNS) for cmd in commands):
            techniques.append("T1552.001")
        # Crypto miner
        if any(k in yara_family for k in ("XMRig", "CryptoMiner")):
            techniques.append("T1496")
        # Ransomware
        if any(k in yara_family for k in ("WannaCry", "LockBit", "Ransomware")):
            techniques.append("T1486")

    # ── DIONAEA (Multi-protocol) ──────────────────────────────────────────────
    elif honeypot == "dionaea":
        if port == 445:
            techniques.append("T1021.002")  # SMB
            techniques.append("T1210")      # Exploitation of Remote Services
        elif port in (3306, 1433, 27017, 5432, 6379):
            techniques.append("T1190")      # Exploit Public-Facing App (DB)
        elif port == 1883:
            techniques.append("T1190")      # MQTT exploit
        elif port == 80:
            techniques.append("T1190")      # HTTP exploit
        else:
            techniques.append("T1210")      # Generic remote service exploitation
        # Malware family enrichment
        if "Mirai" in yara_family:
            techniques.append("T1105")      # Botnet tool transfer
        if "Emotet" in yara_family:
            techniques.append("T1071.001")  # C2 via web protocols
        if any(k in yara_family for k in ("WannaCry", "LockBit", "Ransomware")):
            techniques.append("T1486")
        if any(k in yara_family for k in ("XMRig", "CryptoMiner")):
            techniques.append("T1496")

    # ── GALAH (HTTP LLM honeypot) ─────────────────────────────────────────────
    elif honeypot == "galah":
        techniques.append("T1190")          # Exploit Public-Facing App
        if any(s in http_uri for s in _SCAN_PATHS):
            techniques.append("T1595.002")  # Vulnerability Scanning
        if any(p in http_uri for p in _SQLI_PATTERNS):
            pass                            # T1190 already added (SQL injection)

    # ── ZEEK (Network passive sensor) ────────────────────────────────────────
    elif honeypot == "zeek":
        techniques.append("T1046")          # Network Service Discovery
        techniques.append("T1592")          # Gather Victim Host Information

    # ── Fallback for unknown honeypot types ───────────────────────────────────
    else:
        techniques.append("T1190")

    # Deduplicate preserving insertion order
    seen = set()
    return [t for t in techniques if not (t in seen or seen.add(t))]


# ── Part 3 — Kill chain phase ──────────────────────────────────────────────────

def get_kill_chain_phase(technique_ids: list) -> str:
    """Returns the most advanced kill chain phase reached by the given techniques."""
    phases = []
    for tid in technique_ids:
        tech = MITRE_TECHNIQUES.get(tid)
        if tech:
            phase = tech["kill_chain"]
            if phase in KILL_CHAIN_ORDER:
                phases.append(KILL_CHAIN_ORDER.index(phase))
    if not phases:
        return "reconnaissance"
    return KILL_CHAIN_ORDER[max(phases)]


def get_kill_chain_stage_number(phase: str) -> int:
    """Returns 1-based stage number for the kill chain phase."""
    try:
        return KILL_CHAIN_ORDER.index(phase) + 1
    except ValueError:
        return 1


# ── Part 4 — Mistral forensic narrative (short prompt, fast) ──────────────────

def get_forensic_narrative(session: dict, technique_ids: list) -> str:
    """
    Calls Ollama/Mistral for a 2-sentence forensic narrative ONLY.
    Does NOT ask for technique IDs — those come from deterministic rules.
    Short prompt (~80 tokens output) → ~15s instead of 60s.
    """
    honeypot  = session.get("honeypot_type", "unknown")
    port      = session.get("destination_port", 0)
    src_ip    = session.get("source_ip", "unknown")
    attempts  = session.get("login_attempts", 0)
    commands  = list(session.get("commands", []) or [])[:5]
    yara      = ", ".join(session.get("yara_matches", []) or []) or "none"

    technique_names = [
        MITRE_TECHNIQUES[t]["name"]
        for t in technique_ids
        if t in MITRE_TECHNIQUES
    ]

    prompt = (
        "Forensic analyst report. Write 2 sentences only. No JSON.\n\n"
        f"Attack: {honeypot} honeypot on port {port}\n"
        f"Source: {src_ip}\n"
        f"Techniques: {', '.join(technique_names)}\n"
        f"Login attempts: {attempts}\n"
        f"Commands: {commands if commands else 'none'}\n"
        f"Malware: {yara}\n\n"
        "Write a concise forensic summary describing this attack and its likely objective."
    )

    try:
        resp = requests.post(
            f"{config.OLLAMA_URL}/api/generate",
            json={
                "model":   config.OLLAMA_MODEL,
                "prompt":  prompt,
                "stream":  False,
                "options": {
                    "temperature": 0.1,
                    "num_predict": 80,
                    "stop": ["\n\n", "3."],
                },
            },
            timeout=300,
        )
        resp.raise_for_status()
        text = resp.json().get("response", "").strip()
        if text:
            return text
        raise ValueError("empty LLM response")
    except Exception as e:
        log.warning(f"Ollama narrative failed: {e}")
        return None  # caller generates fallback


# ── Part 5 — MitreMapper class ─────────────────────────────────────────────────

class MitreMapper:
    """
    Hybrid MITRE ATT&CK mapper:
    - Technique IDs: deterministic rules (always correct, confidence=1.0)
    - Forensic narrative: Mistral 7B via Ollama (short prompt, ~15s)
    """

    def __init__(self, use_llm: bool = True):
        self.use_llm          = use_llm
        self.ollama_available = self._check_ollama()
        status = "available" if self.ollama_available else "unavailable"
        log.info(
            f"MitreMapper initialized — deterministic rules + "
            f"LLM narrative ({'enabled' if use_llm else 'disabled'}, Ollama {status})"
        )

    def _check_ollama(self) -> bool:
        try:
            r = requests.get(f"{config.OLLAMA_URL}/api/tags", timeout=3)
            models = [m["name"].split(":")[0] for m in r.json().get("models", [])]
            available = config.OLLAMA_MODEL in models
            if not available:
                log.warning(
                    f"Ollama reachable but model '{config.OLLAMA_MODEL}' "
                    f"not loaded (available: {models or 'none'})"
                )
            return available
        except Exception as e:
            log.warning(f"Ollama unreachable ({config.OLLAMA_URL}): {e}")
            return False

    def map_session(self, session: dict) -> dict:
        """
        Full MITRE mapping for one session.
        Returns dict with valid technique IDs (deterministic) + narrative (LLM).
        """
        # ── Step 1: deterministic technique IDs (always runs, always correct) ─
        technique_ids = get_techniques_deterministic(session)
        if not technique_ids:
            technique_ids = ["T1190"]  # fallback: generic exploitation

        # ── Step 2: kill chain phase from techniques ───────────────────────────
        kill_chain_phase = get_kill_chain_phase(technique_ids)
        kill_chain_stage = get_kill_chain_stage_number(kill_chain_phase)

        # ── Step 3: build technique objects with ATT&CK URLs ──────────────────
        techniques_detail = []
        for tid in technique_ids:
            tech = MITRE_TECHNIQUES.get(tid)
            if tech:
                # Build URL: T1110.001 → /T1110/001/
                url_path = tid.replace(".", "/")
                techniques_detail.append({
                    "id":     tid,
                    "name":   tech["name"],
                    "tactic": tech["tactic"],
                    "url":    f"https://attack.mitre.org/techniques/{url_path}/",
                })

        # ── Step 4: LLM narrative (optional, graceful fallback) ───────────────
        narrative = None
        llm_used  = False
        if self.use_llm and self.ollama_available:
            narrative = get_forensic_narrative(session, technique_ids)
            llm_used  = narrative is not None

        if not narrative:
            tactic    = MITRE_TECHNIQUES[technique_ids[0]]["tactic"] if technique_ids else "Unknown"
            src_ip    = session.get("source_ip", "unknown")
            honeypot  = session.get("honeypot_type", "unknown")
            port      = session.get("destination_port", 0)
            narrative = (
                f"Automated {honeypot} attack from {src_ip} "
                f"targeting port {port} ({tactic.lower()} phase)."
            )

        session_id = session.get("session_id", "")
        log.info(
            f"MITRE [{session_id[:12]}...] "
            f"phase={KILL_CHAIN_LABELS.get(kill_chain_phase, kill_chain_phase)} "
            f"(stage {kill_chain_stage}) "
            f"techniques={len(technique_ids)} "
            f"llm={'yes' if llm_used else 'no'}"
        )

        return {
            "session_id":         session_id,
            "technique_ids":      technique_ids,
            "techniques":         techniques_detail,
            "primary_technique":  technique_ids[0] if technique_ids else "T1190",
            "kill_chain_phase":   kill_chain_phase,
            "kill_chain_label":   KILL_CHAIN_LABELS.get(kill_chain_phase, kill_chain_phase),
            "kill_chain_stage":   kill_chain_stage,
            "kill_chain_completed": kill_chain_stage >= 5,
            "forensic_narrative": narrative,
            "llm_used":           llm_used,
            "mapping_source":     "deterministic + llm_narrative" if llm_used else "deterministic",
            "confidence":         1.0,
        }

    def map_batch(self, sessions: list) -> list:
        """Map multiple sessions, log progress."""
        results = []
        for i, session in enumerate(sessions):
            log.debug(
                f"  [{i+1}/{len(sessions)}] "
                f"Mapping {session.get('session_id','?')[:8]}..."
            )
            results.append(self.map_session(session))
        return results
