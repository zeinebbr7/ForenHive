"""
ForenHive — Configuration générale
Charge toutes les variables depuis le fichier .env ou les variables Docker.
"""

import os
from pathlib import Path


# ── Chargement du fichier .env (hors Docker) ──────────────────────────────────

def charger_env():
    """Lit le fichier .env à la racine du projet et injecte les variables."""
    fichier_env = Path(__file__).parents[1] / ".env"
    if fichier_env.exists():
        for ligne in fichier_env.read_text().splitlines():
            ligne = ligne.strip()
            if ligne and not ligne.startswith("#") and "=" in ligne:
                cle, _, valeur = ligne.partition("=")
                os.environ.setdefault(cle.strip(), valeur.strip())

charger_env()


# ── Elasticsearch ──────────────────────────────────────────────────────────────

ES_HOST  = os.environ.get("ES_HOST",  "forenhive-elasticsearch")
ES_PORT  = int(os.environ.get("ES_PORT", "9200"))
ES_URL   = f"http://{ES_HOST}:{ES_PORT}"
ES_INDEX = "honeypot-logs-*"   # tous les indices journaliers


# ── PostgreSQL ─────────────────────────────────────────────────────────────────

PG_HOST     = os.environ.get("PG_HOST",     "forenhive-postgresql")
PG_PORT     = int(os.environ.get("PG_PORT", "5432"))
PG_DB       = os.environ.get("PG_DB",       "forenhive")
PG_USER     = os.environ.get("PG_USER",     "forenhive")
PG_PASSWORD = os.environ.get("PG_PASSWORD") or os.environ.get("POSTGRES_PASSWORD", "")


# ── Ollama / Mistral 7B (MITRE ATT&CK offline) ────────────────────────────────

OLLAMA_HOST  = os.environ.get("OLLAMA_HOST",  "forenhive-ollama")
OLLAMA_PORT  = int(os.environ.get("OLLAMA_PORT", "11434"))
OLLAMA_URL   = f"http://{OLLAMA_HOST}:{OLLAMA_PORT}"
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "mistral")


# ── Clés API externes ──────────────────────────────────────────────────────────

ABUSEIPDB_KEY  = os.environ.get("ABUSEIPDB_KEY",  "")   # réputation IP
VIRUSTOTAL_KEY = os.environ.get("VIRUSTOTAL_KEY",  "")   # analyse de malwares
SHODAN_KEY     = os.environ.get("SHODAN_KEY",      "")   # scan de ports (non utilisé — on utilise InternetDB gratuit)


# ── Bases GeoIP MaxMind (fichiers .mmdb) ──────────────────────────────────────

GEOIP_CITY_DB = os.environ.get("GEOIP_CITY_DB", "/app/GeoLite2-City.mmdb")
GEOIP_ASN_DB  = os.environ.get("GEOIP_ASN_DB",  "/app/GeoLite2-ASN.mmdb")


# ── Répertoire des binaires capturés par Dionaea ──────────────────────────────

DIONAEA_BINARIES_PATH = os.environ.get(
    "DIONAEA_BINARIES_PATH",
    "/opt/dionaea/var/lib/dionaea/binaries"
)


# ── Répertoire des règles YARA ─────────────────────────────────────────────────

YARA_RULES_DIR = os.environ.get(
    "YARA_RULES_DIR",
    str(Path(__file__).parent / "yara_rules")
)


# ── Paramètres divers ──────────────────────────────────────────────────────────

# Durée de validité du cache d'enrichissement IP (en heures)
ENRICHMENT_CACHE_TTL_HOURS = int(os.environ.get("ENRICHMENT_CACHE_TTL_HOURS", "24"))

# Délai minimum entre deux appels VirusTotal (free tier : 4 req/sec max)
VIRUSTOTAL_RATE_LIMIT_SEC = 0.25
