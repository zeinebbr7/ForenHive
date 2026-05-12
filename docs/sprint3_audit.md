# ForenHive — Sprint 3 Audit
**Forensic Engine: Enrichment · YARA · VirusTotal · Hybrid MITRE Mapper · 18-Signal Risk Scorer**
*Branch: zeineb | Initial: 2026-04-04 · Overhaul: 2026-04-12*

---

## 1. Architecture Overview

Sprint 3 implements the forensic analysis layer that consumes normalized events from Sprint 2 (Elasticsearch) and produces enriched forensic intelligence stored in PostgreSQL.

```
Elasticsearch ──┐
                ├──► forensic-engine ──► PostgreSQL
Dionaea files ──┘    (C3 layer)          (forensic results)
```

**Stack:** Python 3.11 · psycopg2 2.9.9 · elasticsearch-py 8.13.0 · geoip2 4.8.0 · yara-python 4.5.0 · shodan 1.31.0 · ipwhois 1.2.0
**HTTP API:** FastAPI on port 8001 — backend calls forensic-engine via `FORENSIC_ENGINE_URL=http://forensic-engine:8001`

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

**4 columns added to `forensic_sessions` (2026-04-12):**
```sql
kill_chain_phase    VARCHAR(50),   -- e.g. "lateral_movement"
kill_chain_stage    INTEGER,       -- 1-8 (Cyber Kill Chain position)
primary_technique   VARCHAR(20),   -- e.g. "T1021.002"
forensic_narrative  TEXT           -- 2-sentence forensic summary
```
Total: 13 columns. Migration block for existing deployments:
```bash
docker exec forenhive-postgresql psql -U forenhive -d forenhive -c \
  "ALTER TABLE forensic_sessions ADD COLUMN IF NOT EXISTS kill_chain_phase VARCHAR(50);"
# (repeat for kill_chain_stage, primary_technique, forensic_narrative)
```

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
| `GEOIP_CITY_DB` / `GEOIP_ASN_DB` | `/app/GeoLite2-*.mmdb` | MaxMind offline databases (host: `./geoip/`) |
| `DIONAEA_BINARIES_PATH` | `/opt/dionaea/var/lib/dionaea/binaries` | Malware capture directory |
| `YARA_RULES_DIR` | `./yara_rules` | YARA rules directory |
| `ENRICHMENT_CACHE_TTL_HOURS` | `24` | IP cache TTL |
| `PRIVATE_VPN_RANGES` | `10.212.0.0/16` | Comma-separated CIDRs treated as internal VPN (overridable) |
| `ENGINE_INTERVAL_MINUTES` | `1440` | Run interval in minutes (1 day); set via docker-compose env |

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

**Private IP classification *(added 2026-04-12)*:** `_classify_private_ip(ip)` maps RFC 1918 ranges to risk levels:

| IP range | network_class | private_risk_level |
|---|---|---|
| `127.x.x.x` | loopback | **ignore** (skipped entirely) |
| `172.17–19.x` | docker_bridge | **ignore** (skipped entirely) |
| `PRIVATE_VPN_RANGES` (default `10.212.0.0/16`) | vpn_tunnel | investigate |
| `10.0.0.0/8`, `172.16.0.0/12` | corporate_internal | investigate |
| `192.168.0.0/16` | corporate_internal | monitor |

Engine skips scoring for IPs with `private_risk_level == "ignore"`. For all other private IPs `enrich()` returns `{ip, private, network_class, is_docker, private_risk_level}` without external API calls.

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

### 2.6 Risk Score Calculator (`risk_score.py`) *(rewritten 2026-04-12)*

**Function:** `calculate_risk_score(session_data: dict) → dict` *(was `→ int` before overhaul)*

Deterministic weighted scoring — 18 signals, fully auditable, no ML.

| # | Signal | Source | Max pts |
|---|---|---|---|
| 1 | AbuseIPDB confidence score | AbuseIPDB | 40 |
| 2 | AbuseIPDB total reports | AbuseIPDB | 10 |
| 3 | Login volume (tiered: >10 / >50 / >200) | Cowrie/Dionaea | 25 |
| 4 | Login success / actual compromise | Cowrie | 25 |
| 5 | Shell commands executed | Cowrie | 10 |
| 6 | File download (exfil_bytes > 0) | Cowrie/Dionaea | 15 |
| 7 | YARA match — malware family (severity-tiered) | YARA | 30 |
| 8 | VirusTotal malicious count | VirusTotal | 30 |
| 9 | Tor exit node | IPLocate | 15 |
| 10 | VPN / proxy / hosting | IPLocate | 5 |
| 11 | Critical port targeted | Port | 10 |
| 12 | Shodan vulns on attacker IP (botnet zombie) | Shodan | 10 |
| 13 | Exploit CVE probe (EternalBlue etc.) | Dionaea/SMB | 40 |
| 14 | SMB share enumeration | Dionaea | 30 |
| 15 | EPMapper prescan | Dionaea | 15 |
| 16 | Multi-honeypot correlation (IP on >1 honeypot) | Cross-source | 10 |
| 17 | Attack velocity (>2 attempts/second) | Time metrics | 5 |
| 18 | Recidivism (previously seen in PostgreSQL) | PostgreSQL | 10 |

**Private IPs:** reputation signals (1, 2, 9–12) are skipped; behavioral signals are weighted ×2. Loopback and Docker bridge addresses (`127.x`, `172.17-19.x`) are skipped entirely.
**Score cap:** `min(raw_score, 100)`.

**Return dict (13 keys):**

| Key | Content |
|---|---|
| `score` | 0–100 composite score |
| `level` | CRITICAL / HIGH / MEDIUM / LOW / INFO |
| `confidence` | 0.3–1.0 data quality factor |
| `signal_breakdown` | Per-signal points + explanation text (for charts) |
| `attack_types` | Classified categories (brute_force, malware, lateral_movement…) |
| `mitre_techniques` | Deterministic ATT&CK technique objects |
| `lateral_movement` | Bool — True if SMB + credential access detected |
| `data_quality` | Available sources + warnings |
| `notes` | Terse technical flags |
| `narrative` | Human-readable paragraph (for reports) |
| `recommended_actions` | SOC playbook steps |
| `iocs` | IP, hashes, commands, malware families |
| `attribution` | Geo, ASN, attacker profile |

**Risk levels:**

| Score | Level |
|---|---|
| 80–100 | CRITICAL |
| 60–79 | HIGH |
| 40–59 | MEDIUM |
| 20–39 | LOW |
| 0–19 | INFO |

---

### 2.7 MITRE ATT&CK Mapper (`mitre_mapper.py`) *(added 2026-04-12)*

**Class:** `MitreMapper` — hybrid approach: deterministic technique IDs + Mistral 7B narrative only.

**Design:** Full-LLM approach (`ollama_mitre.py`, kept for reference) was abandoned because Mistral 7B invented invalid technique IDs under few-shot prompting. New approach:

| Component | Method | Confidence |
|---|---|---|
| Technique IDs | Deterministic rule engine | 1.0 (zero hallucination) |
| Kill chain phase | Derived from technique metadata | 1.0 |
| Forensic narrative | Mistral 7B via Ollama (80 tokens) | Graceful fallback on timeout |

**15 validated ATT&CK Enterprise technique IDs:**

| ID | Name | Tactic | Kill Chain Stage |
|---|---|---|---|
| T1110.001 | Brute Force: Password Guessing | Credential Access | exploitation |
| T1110.003 | Brute Force: Password Spraying | Credential Access | exploitation |
| T1078 | Valid Accounts | Initial Access | exploitation |
| T1059.004 | Unix Shell | Execution | installation |
| T1105 | Ingress Tool Transfer | C2 | command_and_control |
| T1552.001 | Credentials In Files | Credential Access | actions_on_objectives |
| T1210 | Exploitation of Remote Services | Lateral Movement | exploitation |
| T1190 | Exploit Public-Facing Application | Initial Access | delivery |
| T1595.002 | Active Scanning: Vulnerability Scanning | Reconnaissance | reconnaissance |
| T1046 | Network Service Discovery | Discovery | reconnaissance |
| T1021.002 | SMB/Windows Admin Shares | Lateral Movement | lateral_movement |
| T1486 | Data Encrypted for Impact | Impact | actions_on_objectives |
| T1496 | Resource Hijacking | Impact | actions_on_objectives |
| T1071.001 | Application Layer Protocol: Web | C2 | command_and_control |
| T1592 | Gather Victim Host Information | Reconnaissance | reconnaissance |

**Deterministic rule logic per honeypot:**

| Honeypot | Condition | Technique mapped |
|---|---|---|
| cowrie | login_attempts > 1 | T1110.001 |
| cowrie | login_attempts > 100 | T1110.003 |
| cowrie | success_count > 0 | T1078 |
| cowrie | command_count > 0 | T1059.004 |
| cowrie | exfil_bytes > 0 | T1105 |
| cowrie | credential file in commands | T1552.001 |
| cowrie | XMRig / CryptoMiner YARA | T1496 |
| cowrie | WannaCry / LockBit YARA | T1486 |
| dionaea | port 445 (SMB) | T1021.002 + T1210 |
| dionaea | port 3306/1433/27017/5432/6379 (DB) | T1190 |
| dionaea | Mirai YARA | T1105 |
| dionaea | Emotet YARA | T1071.001 |
| galah | always | T1190 |
| galah | scan paths (/wp-admin, /.env, …) | T1595.002 |
| zeek | always | T1046 + T1592 |

**Performance:** ~30 s/session (80-token narrative) vs ~60 s previously (512-token full JSON). Ollama timeout 60 s; on timeout, narrative falls back to a deterministic template — technique IDs are unaffected.

**`map_session()` return:**
```python
{
  "technique_ids":        ["T1110.001", "T1078"],
  "techniques":           [{"id", "name", "tactic", "url"}, ...],
  "primary_technique":    "T1110.001",
  "kill_chain_phase":     "installation",
  "kill_chain_label":     "Installation",
  "kill_chain_stage":     5,          # 1-8; stage ≥ 5 → kill_chain_completed = True
  "kill_chain_completed": True,
  "forensic_narrative":   "Attacker performed ...",
  "llm_used":             True,       # True only when Ollama returned non-empty text
  "mapping_source":       "deterministic + llm_narrative",
  "confidence":           1.0,
}
```

---

### 2.8 Engine Orchestrator (`engine.py`) *(major rewrite 2026-04-12)*

**Class:** `ForensicEngine`

Coordinates all components in sequence — now queries all three honeypots:

```
run_full_analysis(hours_back=24)
  ├── run_enrichment()        → ES terms agg → IPEnricher.enrich_from_es()
  ├── run_yara_scan()         → YARAScanner.scan_dionaea_downloads()
  │                              └── VirusTotalScanner.lookup_hash() for each match
  ├── run_vt_from_es()        → ES file.hash.sha256 agg → VirusTotalScanner.lookup_batch()
  └── run_session_scoring()
        ├── _query_cowrie_sessions()   → login count, success/failed, commands, bytes
        ├── _query_dionaea_sessions()  → by source IP + destination port
        ├── _query_galah_sessions()    → HTTP events, top-20 paths per IP
        ├── _query_cowrie_commands()   → up to 50 shell commands per session
        └── per session:
              calculate_risk_score(session_data)
              MitreMapper.map_session(session_data)
              _save_session() → PostgreSQL (13 columns)
```

**`_save_session()` — 4 new columns added (2026-04-12):**
```sql
kill_chain_phase, kill_chain_stage, primary_technique, forensic_narrative
```

**CLI flags:**
```
python engine.py                 # full analysis, last 24h
python engine.py --hours 48      # custom lookback
python engine.py --enrich-only   # enrichment only
python engine.py --yara-only     # YARA + VT only
python engine.py --score-only    # scoring only (skips enrichment + YARA)
python engine.py --init-db       # schema init then exit
```

---

### 2.9 Docker Container *(updated 2026-04-12)*

**Dockerfile:** `forensic-engine/Dockerfile`
- Base: `python:3.11-slim`
- System deps: `gcc`, `libssl-dev`, `libmagic1` (required by `yara-python`)
- Runs as root inside container (needed for Dionaea volume read)
- Exposes port 8001 — backend calls this via `FORENSIC_ENGINE_URL`

**docker-compose.yml (current state):**

```yaml
forensic-engine:
  build: ./forensic-engine
  container_name: forenhive-forensic-engine
  restart: unless-stopped
  ports:
    - "8001:8001"
  volumes:
    - dionaea-malware:/opt/dionaea/var/lib/dionaea:ro
    - zeek-logs:/usr/local/zeek/logs:ro
    - ./forensic-engine/yara_rules:/app/yara_rules:ro
    - ./geoip/GeoLite2-City.mmdb:/app/GeoLite2-City.mmdb:ro
    - ./geoip/GeoLite2-ASN.mmdb:/app/GeoLite2-ASN.mmdb:ro
  networks:
    - backend-net
  env_file:
    - .env
  environment:
    - ENGINE_INTERVAL_MINUTES=1440
    - TWILIO_ACCOUNT_SID=${TWILIO_ACCOUNT_SID}
    - TWILIO_AUTH_TOKEN=${TWILIO_AUTH_TOKEN}
    - TWILIO_WA_NUMBER=${TWILIO_WA_NUMBER}
    - DEST_WA=${DEST_WA}
  depends_on:
    - elasticsearch
    - postgresql
```

**Changes from initial design:**
- GeoIP files moved from `/etc/logstash/` to `./geoip/` project directory
- `zeek-logs` volume added (Zeek conn/ssh/http log access for session scoring)
- Port 8001 exposed — backend's `forensic_runner.py` triggers runs via HTTP
- `ENGINE_INTERVAL_MINUTES=1440` — daily schedule; APScheduler in the backend also triggers every 6 h
- Twilio env vars added for WhatsApp alert notifications

---

## 3. File Structure

```
forensic-engine/
├── __init__.py
├── engine.py               ← main orchestrator (Cowrie + Dionaea + Galah)
├── enricher.py             ← IP enrichment (5 sources + PG cache + private IP classification)
├── yara_scanner.py         ← YARA scan + PG persistence
├── virustotal.py           ← VT v3 API + quota handling + PG persistence
├── risk_score.py           ← 18-signal scorer, returns 13-key dict
├── mitre_mapper.py         ← hybrid MITRE mapper (deterministic IDs + LLM narrative)
├── ollama_mitre.py         ← superseded full-LLM approach (kept for reference)
├── config.py               ← env vars (+ PRIVATE_VPN_RANGES)
├── Dockerfile
├── requirements.txt
├── db/
│   ├── schema.sql          ← 4 PostgreSQL tables + 4 new columns (kill chain)
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
| Single `forensic-engine/` directory (not inside `backend/`) | Keeps forensic logic decoupled from the FastAPI layer. Runs independently on its own schedule; backend triggers it via HTTP. |
| PostgreSQL cache for enrichment | Avoids redundant API calls on re-runs. AbuseIPDB free tier is 1000/day — without cache, repeated runs exhaust quota in hours. |
| YARA rules compiled at startup, not per-scan | Compilation is expensive (~100 ms for 6 files). Single compile → many scans is far faster. |
| `ON CONFLICT DO UPDATE` for both YARA and VT | YARA scan and VT lookup write to the same `file_analysis` row. Upsert ensures the most recent result wins without race conditions. |
| Hybrid MITRE (deterministic IDs + LLM narrative) | Full-LLM approach (`ollama_mitre.py`) invented invalid technique IDs under Mistral 7B. Deterministic rules give 100% accurate IDs; LLM is limited to 80-token narrative only. |
| 18-signal risk scorer returns dict (not int) | Backend needs the breakdown dict for per-signal charts, IOC lists, and SOC recommendations — returning only an int would require re-scoring for display. |
| `kill_chain_completed = stage >= 5` | Stage 5+ means attacker achieved persistence or beyond — useful threshold for alerting. |
| Private IP classification (ignore vs investigate) | Docker bridge IPs (`172.17-19.x`) are internal routing noise — scoring them would waste AbuseIPDB quota. Lab Kali (`10.212.x`) is interesting for behavioral signals. |
| GeoIP files moved to `./geoip/` | Both Logstash and forensic-engine need the mmdb files; single project-root location avoids duplication and `/etc/logstash/` host dependency. |
| Single forensic-engine run at a time | Two concurrent containers compete for Ollama CPU → MITRE narrative timeouts. APScheduler in the backend serializes triggers. |

---

## 5. Known Limitations

| Item | Description | Impact |
|---|---|---|
| No real attacker traffic yet | Server not internet-facing — all IPs are RFC 1918 (Kali), so enrichment returns private classification | No real enrichment data until internet deployment |
| AbuseIPDB 1000/day free limit | With many unique IPs, quota exhausts quickly | 24 h PostgreSQL cache mitigates this; upgrade to paid plan for production |
| Shodan free tier | Only 1 lookup/second, no vulnerability data on free plan | `infrastructure.vulns` will be empty on free tier |
| Mistral 7B CPU inference latency | Sometimes >60 s for MITRE narrative on CPU-only server (no GPU) | Narrative falls back to deterministic template; technique IDs unaffected |
| PostgreSQL password reset on container recreate | Docker volume behavior resets user auth | Run `ALTER USER forenhive PASSWORD 'forenhive2026'` after each recreate |
| Dionaea binary path | `scan_dionaea_downloads()` only iterates flat directory; nested subdirs not scanned | Minor — Dionaea typically stores binaries flat |
| `suspect_profiles` table | Table created, no population logic in forensic-engine | Sprint 4 backend `profiler.py` populates this via Groq/Ollama |
| `kill_chain_phase` NULL for rows scored before 2026-04-12 migration | Old rows have NULL in new columns | Backfilled on next `ON CONFLICT DO UPDATE` run |

---

## 6. Sprint 3 Status: COMPLETE ✅

| Component | File | Status |
|---|---|---|
| PostgreSQL schema (4 tables + 4 kill-chain columns) | `db/schema.sql` + `db/init_db.py` | ✅ Complete |
| Configuration (+ `PRIVATE_VPN_RANGES`) | `config.py` | ✅ Complete |
| IP Enrichment + private IP classification | `enricher.py` | ✅ Complete |
| YARA rules (6) | `yara_rules/*.yar` | ✅ Complete |
| YARA scanner | `yara_scanner.py` | ✅ Complete |
| VirusTotal lookup + quota handling | `virustotal.py` | ✅ Complete |
| Risk scoring (18 signals, 13-key dict) | `risk_score.py` | ✅ Complete (rewritten 2026-04-12) |
| Hybrid MITRE ATT&CK mapper | `mitre_mapper.py` | ✅ Complete (added 2026-04-12) |
| Engine orchestrator (Cowrie + Dionaea + Galah) | `engine.py` | ✅ Complete (rewritten 2026-04-12) |
| Docker container (port 8001) | `Dockerfile` + `requirements.txt` | ✅ Complete |
| docker-compose integration | `docker-compose.yml` | ✅ Complete |
| Forensic timeline | — | → Sprint 4 backend (`/api/forensics/timeline`) |
| SHA-256 + RFC 3161 custody | — | → Sprint 4 backend (`services/chain_custody.py`) |
| FastAPI backend (C4) | `backend/` | → Sprint 4 ✅ |
| React frontend (C5) | `frontend/` | → Sprint 5 🔲 |
