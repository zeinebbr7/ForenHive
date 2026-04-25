# ForenHive — Sprint 3 Audit
**Forensic Engine: Enrichment · YARA · VirusTotal · Risk Scoring**
*Branch: zeineb | Date: 2026-04-04*

---

## 1. Architecture Overview

Sprint 3 implements the forensic analysis layer that consumes normalized events from Sprint 2 (Elasticsearch) and produces enriched forensic intelligence stored in PostgreSQL.

```
Elasticsearch ──┐
                ├──► forensic-engine ──► PostgreSQL
Dionaea files ──┘    (C3 layer)          (forensic results)
```

**Stack:** Python 3.11 · psycopg2 2.9.9 · elasticsearch-py 8.13.0 · geoip2 4.8.0 · yara-python 4.5.0 · shodan 1.31.0 · ipwhois 1.2.0

---

## 2. Components Implemented

### 2.1 PostgreSQL Schema

**File:** `forensic-engine/db/schema.sql`
**Init script:** `forensic-engine/db/init_db.py`

Four tables created:

| Table | Primary Key | Purpose |
|---|---|---|
| `ip_enrichment_cache` | `ip VARCHAR(45)` | 24h TTL cache for all external API results |
| `file_analysis` | `sha256 VARCHAR(64)` | YARA matches + VirusTotal results per file |
| `forensic_sessions` | `session_id VARCHAR(100)` | One row per attacker session, risk score 0-100 |
| `suspect_profiles` | `id SERIAL` | LLM-generated attacker profiles (Sprint 3 extension) |

**Indexes:** `forensic_sessions` indexed on `source_ip`, `risk_score DESC`, `honeypot_type`, `started_at DESC` for fast dashboard queries.

**Init command:**
```bash
docker compose run --rm forensic-engine python db/init_db.py
```

---

### 2.2 Configuration (`config.py`)

Single source of truth for all environment variables. Reads from `.env` at project root (for local runs) or from Docker env injection.

| Variable | Default | Purpose |
|---|---|---|
| `ES_HOST` / `ES_PORT` | `forenhive-elasticsearch:9200` | Elasticsearch endpoint |
| `PG_HOST` / `PG_PORT` / `PG_DB` | `forenhive-postgresql:5432/forenhive` | PostgreSQL connection |
| `OLLAMA_HOST` / `OLLAMA_MODEL` | `forenhive-ollama:11434 / mistral` | LLM endpoint |
| `ABUSEIPDB_KEY` | — | AbuseIPDB v2 API key |
| `VIRUSTOTAL_KEY` | — | VirusTotal v3 API key |
| `SHODAN_KEY` | — | Shodan API key |
| `GEOIP_CITY_DB` / `GEOIP_ASN_DB` | `/app/GeoLite2-*.mmdb` | MaxMind offline databases |
| `DIONAEA_BINARIES_PATH` | `/opt/dionaea/var/lib/dionaea/binaries` | Malware capture directory |
| `YARA_RULES_DIR` | `./yara_rules` | YARA rules directory |
| `ENRICHMENT_CACHE_TTL_HOURS` | `24` | IP cache TTL |

---

### 2.3 IP Enricher (`enricher.py`)

**Class:** `IPEnricher`

Five-stage pipeline per IP, with PostgreSQL caching:

| Stage | Source | Fields produced | Rate limit |
|---|---|---|---|
| GeoIP | MaxMind GeoLite2-City + ASN (offline) | `country`, `city`, `lat`, `lon`, `asn`, `org` | None |
| Privacy | IPLocate API (free, no key) | `is_tor`, `is_vpn`, `is_proxy`, `is_hosting` | None |
| Reputation | AbuseIPDB v2 | `abuse_score`, `total_reports`, `isp`, `is_tor` | 1000/day |
| Infrastructure | Shodan | `open_ports`, `vulns`, `hostnames`, `os`, `tags` | 1 req/sec |
| Whois | RDAP (ipwhois) | `network`, `org`, `cidr` | None |

**Private IP handling:** RFC 1918 addresses (`10.x`, `172.16-31.x`, `192.168.x`) are detected via `ipaddress.ip_address().is_private` and returned immediately without any external calls.

**Cache logic:**
- `check_cache(ip)` → returns cached dict if `expires_at > NOW()`
- `save_cache(ip, data)` → upserts with `expires_at = NOW() + 24h`
- Shodan is called **after** cache check, eliminating redundant API calls

**Batch method:** `enrich_from_es(es_client, hours_back)` — queries ES for `distinct source.ip` using a terms aggregation (up to 10 000 IPs), then enriches each.

**Output structure:**
```json
{
  "ip": "185.220.101.5",
  "geo": {"country": "Germany", "city": "Frankfurt", "lat": 50.11, "lon": 8.68, "asn": 24940, "org": "Hetzner"},
  "privacy": {"is_tor": true, "is_vpn": false, "is_proxy": false, "is_hosting": true},
  "reputation": {"abuse_score": 100, "total_reports": 5432, "isp": "Hetzner Online GmbH", "is_tor": true},
  "infrastructure": {"open_ports": [22, 80, 443], "vulns": [], "hostnames": []},
  "whois": {"network": "Hetzner-...", "org": "Hetzner Online GmbH", "cidr": "185.220.96.0/19"},
  "enriched_at": "2026-04-04T10:00:00+00:00"
}
```

---

### 2.4 YARA Scanner (`yara_scanner.py`)

**Class:** `YARAScanner`

Compiles all `*.yar` files in `yara_rules/` at startup using `yara.compile(filepaths=...)`. Scans every file in the Dionaea binaries volume.

**YARA rules created (6 files):**

| Rule file | Rules inside | Targets |
|---|---|---|
| `mirai.yar` | `Mirai_Botnet` | ELF binaries with Mirai C2/string artifacts |
| `wannacry.yar` | `WannaCry_Ransomware` | WannaCry strings + EternalBlue SMB marker |
| `emotet.yar` | `Emotet_Loader` | PowerShell dropper patterns + VBA macro artifacts |
| `generic_shell.yar` | `Generic_Reverse_Shell`, `Webshell_Generic` | `/dev/tcp/`, PHP shells, meterpreter, `eval(base64` |
| `crypto_miner.yar` | `CryptoMiner_XMRig`, `CryptoMiner_Generic` | Stratum protocol, XMR wallet regex, XMRig strings |
| `credential_stealer.yar` | `Credential_Stealer`, `SSH_Brute_Tool` | `/etc/shadow`, mimikatz, browser credential paths |

**Per-file result:**
```json
{
  "filepath": "/opt/dionaea/var/lib/dionaea/binaries/abc123",
  "sha256": "e3b0c44298fc1c149afb...",
  "matched": true,
  "matches": [
    {"rule": "Mirai_Botnet", "namespace": "mirai", "meta": {"severity": "critical"}, "strings": [...]}
  ]
}
```

**PostgreSQL persistence:** Every scanned file is written to `file_analysis(sha256, yara_matches)`, even if no rules matched (clean record).

---

### 2.5 VirusTotal Scanner (`virustotal.py`)

**Class:** `VirusTotalScanner`

Uses VirusTotal v3 REST API (`GET /files/{sha256}`).

**Rate limiting:** 0.25s between requests (4 req/sec, free tier).

**HTTP responses handled:**
- `200` → parse and normalize result
- `404` → hash unknown to VT (new/rare malware), returns `None`
- `429` → rate limit hit, backs off 60s and retries

**Output structure:**
```json
{
  "sha256": "abc123...",
  "detection_ratio": "45/75",
  "malicious": 45,
  "suspicious": 2,
  "undetected": 28,
  "family": "Mirai",
  "tags": ["botnet", "elf", "mirai"],
  "first_seen": 1705276800,
  "last_seen": 1743120000,
  "names": ["mirai.arm7", "botnet.linux"]
}
```

**PostgreSQL persistence:** Upserts into `file_analysis(sha256, virustotal_result)`. Compatible with YARA writes — both merge into the same row via `ON CONFLICT DO UPDATE`.

---

### 2.6 Risk Score Calculator (`risk_score.py`)

**Function:** `calculate_risk_score(session_data: dict) → int`

Deterministic weighted scoring (no ML, fully auditable):

| Signal | Max pts | Logic |
|---|---|---|
| IP abuse score | 40 | `AbuseIPDB score × 0.40` |
| Tor / VPN / proxy | 10 | Any one set → +10 |
| YARA match | 20 | Critical families (Mirai/WannaCry/Emotet) → +20, others → +12 |
| VirusTotal detections | 15 | >10 engines → +15, >0 → +8 |
| Login attempt volume | 10 | >500 → +10, >100 → +5, >10 → +2 |
| Critical port targeting | 5 | Ports 445/1433/27017/3306/5432/6379/2375/9200 → +5 |
| Commands executed | 5 | >20 cmds → +5, >5 → +2 |
| Data exfiltration | 5 | >1MB → +5, >100KB → +2 |
| **Max total** | **100** | `min(score, 100)` |

**Risk levels:**

| Score | Level |
|---|---|
| 80–100 | CRITICAL |
| 60–79 | HIGH |
| 40–59 | MEDIUM |
| 20–39 | LOW |
| 0–19 | INFO |

---

### 2.7 Engine Orchestrator (`engine.py`)

**Class:** `ForensicEngine`

Coordinates all components in sequence:

```
run_full_analysis(hours_back=24)
  ├── run_enrichment()       → ES terms agg → IPEnricher.enrich_from_es()
  ├── run_yara_scan()        → YARAScanner.scan_dionaea_downloads()
  │                             └── VirusTotalScanner.lookup_hash() for each YARA match
  ├── run_vt_from_es()       → ES file.hash.sha256 agg → VirusTotalScanner.lookup_batch()
  └── run_session_scoring()  → ES session agg → calculate_risk_score() → _save_session()
```

**Session query:** Aggregates Cowrie sessions from ES using nested `terms` + metric aggregations (login count, command count, bytes sum, first/last timestamp) in a single ES request.

**CLI flags:**
```
python engine.py                 # full analysis, last 24h
python engine.py --hours 48      # custom lookback
python engine.py --enrich-only   # enrichment only
python engine.py --yara-only     # YARA + VT only
python engine.py --init-db       # schema init then exit
```

---

### 2.8 Docker Container

**Dockerfile:** `forensic-engine/Dockerfile`
- Base: `python:3.11-slim`
- System deps: `gcc`, `libssl-dev`, `libmagic1` (required by `yara-python`)
- Runs as root inside container (needed for Dionaea volume read)

**docker-compose.yml additions:**

```yaml
forensic-engine:
  build: ./forensic-engine
  container_name: forenhive-forensic-engine
  restart: unless-stopped
  volumes:
    - dionaea-malware:/opt/dionaea/var/lib/dionaea:ro
    - ./forensic-engine/yara_rules:/app/yara_rules:ro
    - /etc/logstash/GeoLite2-City.mmdb:/app/GeoLite2-City.mmdb:ro
    - /etc/logstash/GeoLite2-ASN.mmdb:/app/GeoLite2-ASN.mmdb:ro
  networks:
    - backend-net
  env_file:
    - .env
  depends_on:
    - elasticsearch
    - postgresql
```

GeoIP mmdb files reuse the existing files already present on the host from the Sprint 2 Logstash setup.

---

## 3. File Structure

```
forensic-engine/
├── __init__.py
├── engine.py               ← main orchestrator
├── enricher.py             ← IP enrichment (5 sources + PG cache)
├── yara_scanner.py         ← YARA scan + PG persistence
├── virustotal.py           ← VT v3 API + PG persistence
├── risk_score.py           ← deterministic 0-100 scoring
├── config.py               ← env vars
├── Dockerfile
├── requirements.txt
├── db/
│   ├── schema.sql          ← 4 PostgreSQL tables
│   └── init_db.py          ← schema init with PG readiness wait
└── yara_rules/
    ├── mirai.yar
    ├── wannacry.yar
    ├── emotet.yar
    ├── generic_shell.yar
    ├── crypto_miner.yar
    └── credential_stealer.yar
```

---

## 4. Design Decisions

| Decision | Rationale |
|---|---|
| Single `forensic-engine/` directory (not inside `backend/`) | Keeps forensic logic decoupled from the FastAPI layer (Sprint 3 backend). Can run independently on a cron schedule. |
| PostgreSQL cache for enrichment | Avoids redundant API calls on re-runs. AbuseIPDB free tier is 1000/day — without cache, repeated runs exhaust quota. |
| YARA rules compiled at startup, not per-scan | Compilation is expensive (~100ms for 6 files). Single compile → many scans is far faster. |
| `ON CONFLICT DO UPDATE` for both YARA and VT | YARA scan and VT lookup write to the same `file_analysis` row. Upsert ensures the most recent result wins without race conditions. |
| Deterministic risk score (no ML) | Reproducible, auditable, explainable for the PFE academic context. Score derivation can be shown step-by-step in a report. |
| Private IP early return | All current traffic is from the internal Kali machine (172.16.x.x). Without this check every test run would hammer external APIs with RFC 1918 addresses. |
| GeoIP reuses Sprint 2 mmdb files | The files are already on the host at `/etc/logstash/`. Avoids a redundant 60 MB download and keeps a single copy updated. |

---

## 5. Known Limitations

| Item | Description | Impact |
|---|---|---|
| No real attacker traffic yet | Server not internet-facing — all IPs are RFC 1918 (Kali), so enrichment always returns `{"private": true}` | No real enrichment data until deployment |
| AbuseIPDB 1000/day free limit | With many unique IPs, quota exhausts quickly | Cache mitigates this; upgrade to paid plan for production |
| Shodan free tier | Only 1 lookup/second, no vulnerability data on free plan | `infrastructure.vulns` will be empty on free tier |
| No periodic scheduling | `engine.py` runs once and exits; no cron/loop built in | Run via `docker compose run` or add a cron job on the host |
| Dionaea binary path | Dionaea stores binaries under `binaries/` but subdirectory layout may vary by version | `scan_dionaea_downloads()` only iterates flat directory; nested subdirs not scanned |
| MITRE ATT&CK mapping | Planned (Ollama/Mistral 7B) but not implemented | `mitre_techniques` column in `forensic_sessions` populated as empty list |
| `suspect_profiles` table | Table created, no population logic yet | Reserved for LLM profiling in Sprint 3 extension |

---

## 6. Sprint 3 Status

| Component | File | Status |
|---|---|---|
| PostgreSQL schema | `db/schema.sql` + `db/init_db.py` |  Complete |
| Configuration | `config.py` |  Complete |
| IP Enrichment | `enricher.py` |  Complete |
| YARA rules (6) | `yara_rules/*.yar` |  Complete |
| YARA scanner | `yara_scanner.py` |  Complete |
| VirusTotal lookup | `virustotal.py` |  Complete |
| Risk scoring | `risk_score.py` |  Complete |
| Engine orchestrator | `engine.py` |  Complete |
| Docker container | `Dockerfile` + `requirements.txt` |  Complete |
| docker-compose integration | `docker-compose.yml` |  Complete |
| MITRE ATT&CK via Ollama | — |  Not started |
| Forensic timeline | — |  Not started |
| SHA-256 + RFC 3161 custody | — |  Not started |
| FastAPI backend (C4) | `backend/` |  Not started |
| React frontend (C5) | `frontend/` |  Not started |
