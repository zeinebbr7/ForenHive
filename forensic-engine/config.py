"""
ForenHive Forensic Engine — Configuration
Loads all environment variables from .env (or Docker env).
"""

import os
from pathlib import Path

def _load_dotenv():
    """Load .env from project root if running outside Docker."""
    env_file = Path(__file__).parents[1] / ".env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                os.environ.setdefault(k.strip(), v.strip())

_load_dotenv()

# ── Elasticsearch ──────────────────────────────────────────────────────────────
ES_HOST  = os.environ.get("ES_HOST",  "forenhive-elasticsearch")
ES_PORT  = int(os.environ.get("ES_PORT",  "9200"))
ES_URL   = f"http://{ES_HOST}:{ES_PORT}"
ES_INDEX = "honeypot-logs-*"

# ── PostgreSQL ─────────────────────────────────────────────────────────────────
PG_HOST     = os.environ.get("PG_HOST",     "forenhive-postgresql")
PG_PORT     = int(os.environ.get("PG_PORT", "5432"))
PG_DB       = os.environ.get("PG_DB",       "forenhive")
PG_USER     = os.environ.get("PG_USER",     "forenhive")
PG_PASSWORD = os.environ.get("PG_PASSWORD") or os.environ.get("POSTGRES_PASSWORD", "")

# ── Ollama / LLM ───────────────────────────────────────────────────────────────
OLLAMA_HOST  = os.environ.get("OLLAMA_HOST",  "forenhive-ollama")
OLLAMA_PORT  = int(os.environ.get("OLLAMA_PORT",  "11434"))
OLLAMA_URL   = f"http://{OLLAMA_HOST}:{OLLAMA_PORT}"
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "mistral")

# ── External API keys ──────────────────────────────────────────────────────────
ABUSEIPDB_KEY   = os.environ.get("ABUSEIPDB_KEY",   "")
VIRUSTOTAL_KEY  = os.environ.get("VIRUSTOTAL_KEY",  "")
SHODAN_KEY      = os.environ.get("SHODAN_KEY",      "")

# ── GeoIP databases (MaxMind mmdb files) ───────────────────────────────────────
GEOIP_CITY_DB = os.environ.get("GEOIP_CITY_DB", "/app/GeoLite2-City.mmdb")
GEOIP_ASN_DB  = os.environ.get("GEOIP_ASN_DB",  "/app/GeoLite2-ASN.mmdb")

# ── Dionaea malware binaries ───────────────────────────────────────────────────
DIONAEA_BINARIES_PATH = os.environ.get(
    "DIONAEA_BINARIES_PATH",
    "/opt/dionaea/var/lib/dionaea/binaries"
)

# ── YARA rules directory ───────────────────────────────────────────────────────
YARA_RULES_DIR = os.environ.get(
    "YARA_RULES_DIR",
    str(Path(__file__).parent / "yara_rules")
)

# ── Cache TTL ──────────────────────────────────────────────────────────────────
ENRICHMENT_CACHE_TTL_HOURS = int(os.environ.get("ENRICHMENT_CACHE_TTL_HOURS", "24"))

# ── Rate limiting ──────────────────────────────────────────────────────────────
SHODAN_RATE_LIMIT_SEC    = 1.0   # 1 req/sec
ABUSEIPDB_DAILY_LIMIT    = 1000  # free tier
VIRUSTOTAL_RATE_LIMIT_SEC = 0.25  # 4 req/sec (free tier)
