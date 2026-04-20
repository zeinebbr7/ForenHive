# ForenHive — Claude Instructions

## Project Identity
- **PFE 2025/2026** — ISET Radès, RSI specialization
- **Students:** Zeineb Benrhouma & Ismail Cherif
- **Host company:** Standard Sharing Software (3S), Charguia, Tunis
- **Server:** Dell PowerEdge R750 · Ubuntu 24.10 · Docker 28.4.0 · IP: 172.16.1.100
- **Network interface:** `eno12399` (hardcoded in Zeek startup command)
- **Branch:** `zeineb` (main is `main`)

## Architecture — 5 Layers
```
C1 Honeypots → C2 ETL Pipeline → C3 Forensic Engine → C4 Backend (FastAPI) → C5 Interface (React)
```
Dual storage: Elasticsearch (attack logs) + PostgreSQL (users/auth/reports/audit)

---

## Sprint Status

### Sprint 1 ✅ — Honeypots (Complete)
All 4 honeypots running. See `docs/sprint1_audit.md` for full details.

| Container | Image | Ports | Status |
|---|---|---|---|
| `forenhive-cowrie` | `cowrie/cowrie:latest` | 2222 (SSH), 2223 (Telnet) | ✅ |
| `forenhive-dionaea` | `dinotools/dionaea:latest` | 23,80,135,443,445,1433,1723,1883,3306,11211,27017 | ✅ |
| `forenhive-galah` | built from `honeypots/galah/galah-src/` | 8080, 8888 | ✅ |
| `forenhive-zeek` | `zeek/zeek:latest` | host network | ✅ |
| `forenhive-ollama` | `ollama/ollama:latest` | 11434 (internal) | ✅ |

### Sprint 2 ✅ — ETL Pipeline (Complete)
Full pipeline operational. See `docs/sprint2_audit.md` for full details.

| Container | Role | Status |
|---|---|---|
| `forenhive-filebeat` | Tail honeypot logs → Logstash:5044 | ✅ |
| `forenhive-logstash` | ECS normalization, GeoIP, per-honeypot filters | ✅ |
| `forenhive-elasticsearch` | Daily indices `honeypot-logs-YYYY.MM.dd` | ✅ |
| `forenhive-postgresql` | postgres:15, DB: forenhive (schema: Sprint 3) | ✅ up, empty |

**Live metrics (2026-03-28):** 11.4M total events across 4 daily indices.

### Sprint 3 🔄 — Forensic Engine (Planned, not started)
- AbuseIPDB enrichment + MaxMind GeoLite2-ASN + IPLocate (Tor/VPN detection)
- YARA scanning on Dionaea captured malware binaries
- VirusTotal SHA-256 lookup
- MITRE ATT&CK mapping via Ollama + Mistral 7B (offline, no API key)
- Forensic timeline (multi-source ms-precision correlation)
- SHA-256 + RFC 3161 chain of custody
- Risk score 0-100 per event/session
- FastAPI backend (REST API, JWT auth) — files are empty placeholders
- React frontend (dashboard, attack map, timeline) — files are empty placeholders
- Nginx (reverse proxy, SSL termination) — config is empty placeholder
- PostgreSQL schema creation

---

## Key File Paths

| File | Purpose |
|---|---|
| `docker-compose.yml` | Full stack orchestration |
| `.env` | Runtime secrets (not committed) |
| `.env.example` | Variable template |
| `Makefile` | `up / down / restart / logs / status / rebuild-galah / ps` |
| `pipeline/filebeat/filebeat.yml` | 4 inputs → Logstash output |
| `pipeline/logstash/logstash.yml` | Workers=4, batch=125, http.host=127.0.0.1 |
| `pipeline/logstash/pipelines/main.conf` | ECS normalization pipeline (single pipeline) |
| `honeypots/cowrie/cowrie.cfg` | SSH hostname=db-prod, auth_class=UserDB |
| `honeypots/cowrie/userdb.txt` | 14 credentials — MUST be pure ASCII (no UTF-8) |
| `honeypots/galah/galah-src/config/config.yaml` | LLM system prompt (example-based, not rule-based) |
| `honeypots/dionaea/smb.yaml` | SMB identity: WIN-SERVER2019 |
| `honeypots/zeek/local.zeek` | Protocol modules + JSON output |
| `docs/architecture.md` | Full architecture reference |
| `docs/sprint1_audit.md` | Sprint 1 bugs, fixes, known issues |
| `docs/sprint2_audit.md` | Sprint 2 bugs, fixes, field mappings, live metrics |

---

## Docker Networks
- **honeypot-net:** Cowrie, Dionaea, Galah, Zeek (attack surface)
- **backend-net:** Filebeat, Logstash, Elasticsearch, PostgreSQL, Ollama, Galah (internal only)

## Docker Volumes (critical)
- `zeek-logs` + `zeek-spool` — **both must be mounted at same absolute path in Zeek AND Filebeat** because `logs/current` is a symlink to `/usr/local/zeek/spool/zeek`
- `cowrie-var` — external volume, shared between Cowrie and Filebeat
- `ollama-models` — external volume, 4.4 GB Mistral 7B weights

---

## Known Recurring Issues

| Issue | Workaround |
|---|---|
| Dionaea log stops writing after extended runtime (~424 MB) | `docker compose restart dionaea` |
| Zeek interface hardcoded as `eno12399` | If NIC renamed, recreate Zeek container |
| GeoIP fails on Docker 172.x IPs | Expected — only public attacker IPs resolve |
| Honeypots not yet internet-facing | All current events are local test traffic from Kali; no real attackers yet |

---

## Working Conventions

- Logstash uses a **single pipeline** (`main.conf`) with if/else on tags — multiple pipeline files caused port conflicts in the past
- Cowrie `userdb.txt` must be **pure ASCII** — Cowrie opens it with `encoding="ascii"` and crashes on any UTF-8 byte
- Galah system prompt must be **example-based** (show exact JSON output), not rule-based — Mistral 7B ignores abstract rules
- Galah Dockerfile requires **CGO_ENABLED=1** (go-sqlite3 needs C bindings)
- Logstash `date` filter uses `timezone: Africa/Tunis` (GMT+1) for all honeypots
- Elasticsearch has **no auth** (`xpack.security.enabled=false`) — dev mode only
- All forensic decisions should favor **completeness and chain of custody** (PFE academic + industry context)
