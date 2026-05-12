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

### Sprint 3 ✅ — Forensic Engine (Complete, updated 2026-04-12)
See `docs/sprint3_audit.md` + `docs/updates on sprint 3` for full details.

| Component | File | Status |
|---|---|---|
| PostgreSQL schema (4 tables) | `forensic-engine/db/schema.sql` | ✅ |
| IP enrichment (5 sources + PG cache) | `forensic-engine/enricher.py` | ✅ |
| YARA scanner (6 rule files) | `forensic-engine/yara_scanner.py` | ✅ |
| VirusTotal v3 lookup | `forensic-engine/virustotal.py` | ✅ |
| Risk scorer (18 signals, returns dict) | `forensic-engine/risk_score.py` | ✅ |
| Hybrid MITRE mapper (deterministic IDs + LLM narrative) | `forensic-engine/mitre_mapper.py` | ✅ |
| Engine orchestrator (Cowrie + Dionaea + Galah) | `forensic-engine/engine.py` | ✅ |
| Docker container | `forensic-engine/Dockerfile` | ✅ |

**Key facts:** 18-signal risk scorer returns a 13-key dict. MITRE technique IDs are deterministic (zero hallucination); Mistral 7B generates the narrative only. Kill chain stage 1–8 stored in `forensic_sessions`. Private IP classification distinguishes Docker bridge / loopback (ignore) from corporate / VPN (investigate).

### Sprint 4 ✅ — Backend API (Complete, 2026-05-12)
See `docs/sprint4_audit.md` for full details.

| Component | File(s) | Status |
|---|---|---|
| FastAPI app + RFC 7807 errors | `backend/main.py` | ✅ |
| JWT auth (access 30 min + refresh 7 d) | `backend/routers/auth.py` | ✅ |
| Attacks API + SSE live stream | `backend/routers/attacks.py` | ✅ |
| Sessions API | `backend/routers/sessions.py` | ✅ |
| Geo API (5 endpoints) | `backend/routers/geo.py` | ✅ |
| Alert engine (8 triggers) + watcher (15 s poll) | `backend/services/alert_engine.py` | ✅ |
| Risk score API (18-signal breakdown) | `backend/routers/risk_score.py` | ✅ |
| Forensics API (timeline, YARA, sessions) | `backend/routers/forensics.py` | ✅ |
| Reports API (HTML + PDF + RFC 3161 custody) | `backend/routers/reports.py` | ✅ |
| Attacker profiling (Mistral 7B / Groq) | `backend/routers/profiling.py` | ✅ |
| AI chat HIVE (Groq SSE + Ollama fallback) | `backend/routers/chat.py` | ✅ |
| Audit log | `backend/routers/audit.py` | ✅ |
| Honeypot container admin | `backend/routers/honeypots.py` | ✅ |
| Unit tests (4 files) | `backend/tests/` | ✅ |

**44 API endpoints total.** APScheduler triggers forensic engine every 6 h. Chain of custody: SHA-256 + FreeTSA RFC 3161 token on every report.

### Sprint 5 🔲 — React Frontend (C5, Not Started)
- Dashboard (attack map, risk timeline, honeypot stats)
- Session explorer + forensic timeline view
- Report viewer (HTML/PDF download)
- Alert management UI
- AI chat (HIVE) interface
- Nginx reverse proxy + SSL termination

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
| `docs/sprint3_audit.md` | Sprint 3 forensic engine components, schema, design decisions |
| `docs/updates on sprint 3` | Sprint 3 overhaul: 18-signal scorer, hybrid MITRE mapper, multi-honeypot engine |
| `docs/sprint4_audit.md` | Sprint 4 FastAPI backend: 44 endpoints, alert engine, reports, chain of custody |

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
