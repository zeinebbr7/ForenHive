# ForenHive — Architecture
**Automated Honeypot-Based Forensic Analysis Platform**
*PFE 2025/2026 — ISET Radès, RSI | Standard Sharing Software (3S), Charguia, Tunis*
*Students: Zeineb Benrhouma & Ismail Cherif*

---

## 1. Overview

ForenHive is a full-stack forensic platform that deploys a set of honeypots to attract and capture cyberattacks, processes the generated logs through an ETL pipeline, enriches them with threat intelligence, and exposes the results through a REST API and web dashboard.

**Infrastructure:** Dell PowerEdge R750 · Ubuntu 24.10 · Docker 28.4.0 · IP: 172.16.1.100

---

## 2. Layer Architecture

```
┌─────────────────────────────────────────────────────┐
│  C5 — Interface (React)                             │
│       Web dashboard · Attack map · Reports          │
└────────────────────┬────────────────────────────────┘
                     │ HTTP
┌────────────────────▼────────────────────────────────┐
│  C4 — Backend (FastAPI)                             │
│       REST API · Auth (JWT) · Risk scoring          │
│       YARA · MITRE ATT&CK · PDF reports             │
└──────────┬──────────────────────┬───────────────────┘
           │ SQL                  │ HTTP
┌──────────▼──────────┐  ┌───────▼──────────────────┐
│  PostgreSQL 15      │  │  Elasticsearch 8.13       │
│  Users · Auth       │  │  honeypot-logs-YYYY.MM.dd │
│  Reports · Audit    │  │  ~2.3M events/day         │
└─────────────────────┘  └───────▲──────────────────┘
                                 │
┌────────────────────────────────┴────────────────────┐
│  C2 — ETL Pipeline                                  │
│  Filebeat 8.13 → Logstash 8.13 → Elasticsearch     │
│  ECS normalization · GeoIP enrichment · Daily index │
└────────────────────┬────────────────────────────────┘
                     │ log files (shared volumes)
┌────────────────────▼────────────────────────────────┐
│  C1 — Honeypots                                     │
│  Cowrie · Dionaea · Galah · Zeek                    │
└─────────────────────────────────────────────────────┘
```

---

## 3. Docker Network Topology

Two isolated Docker bridge networks separate honeypot traffic from backend services:

```
Internet / Host
     │
     ├── ports 2222,2223 ──► forenhive-cowrie   ─┐
     ├── ports 80,443,445,... ► forenhive-dionaea ├── honeypot-net
     ├── ports 8080,8888 ──► forenhive-galah    ─┤
     │   (host network)     forenhive-zeek       ─┘
     │
     │                      forenhive-galah    ─┐
     │                      forenhive-filebeat  ├── backend-net
     │                      forenhive-logstash  │
     │                      forenhive-es        │
     │                      forenhive-postgres  │
     │                      forenhive-ollama   ─┘
```

- **honeypot-net** — attack surface network. Honeypots exposed here receive attacker traffic.
- **backend-net** — internal processing network. Never exposed to the internet.
- **Galah** and **Filebeat** are connected to both networks (Galah needs Ollama; Filebeat needs to reach Logstash).

---

## 4. Component Inventory

### 4.1 Honeypots (Sprint 1)

| Container | Image | Ports | Role |
|---|---|---|---|
| `forenhive-cowrie` | `cowrie/cowrie:latest` | 2222 (SSH), 2223 (Telnet) | SSH/Telnet honeypot — captures credentials, commands, session recordings |
| `forenhive-dionaea` | `dinotools/dionaea:latest` | 23,80,135,443,445,1433,1723,1883,3306,11211,27017 | Multi-protocol malware honeypot — SMB, MySQL, MSSQL, HTTP, MQTT, MongoDB |
| `forenhive-galah` | built from `galah-src` | 8080, 8888 | LLM web honeypot — generates realistic HTML responses via Mistral 7B |
| `forenhive-zeek` | `zeek/zeek:latest` | host network | Passive network analyzer — conn, SSH, HTTP, DNS, FTP logs |

### 4.2 ETL Pipeline (Sprint 2)

| Container | Image | Port | Role |
|---|---|---|---|
| `forenhive-filebeat` | `filebeat:8.13.0` | — | Tail honeypot log files, forward to Logstash via Beats protocol |
| `forenhive-logstash` | `logstash:8.13.0` | 5044 | ECS normalization, GeoIP enrichment, per-honeypot field mapping |
| `forenhive-elasticsearch` | `elasticsearch:8.13.0` | 9200 (internal) | Time-series event store, daily rolling indices |

### 4.3 Storage

| Container | Image | Role |
|---|---|---|
| `forenhive-elasticsearch` | `elasticsearch:8.13.0` | Attack log storage — `honeypot-logs-YYYY.MM.dd` indices |
| `forenhive-postgresql` | `postgres:15` | Relational storage — users, auth tokens, forensic reports, audit trail |

### 4.4 LLM

| Container | Image | Role |
|---|---|---|
| `forenhive-ollama` | `ollama/ollama:latest` | Serves Mistral 7B Q4_K_M (4.4 GB) for Galah web response generation and Sprint 3 MITRE ATT&CK mapping |

### 4.5 Future (Sprint 3)

| Component | Role |
|---|---|
| FastAPI backend | REST API, JWT auth, risk scoring, YARA, MITRE mapping, PDF reports |
| React frontend | Dashboard, attack map, timeline, report viewer |
| Nginx | Reverse proxy, SSL termination |

---

## 5. Volume Architecture

| Volume | Used by | Contains |
|---|---|---|
| `cowrie-var` (external) | Cowrie, Filebeat | Cowrie runtime data, JSON event logs |
| `dionaea-logs` (external) | Dionaea, Filebeat | Dionaea plain-text logs |
| `dionaea-malware` (external) | Dionaea | Captured malware samples |
| `zeek-logs` (external) | Zeek, Filebeat | Rotated daily Zeek log archives |
| `zeek-spool` | Zeek, Filebeat | Live Zeek spool (symlink target — must be shared at same absolute path) |
| `galah-logs` | Galah, Filebeat | `event_log.json`, `cache.db` |
| `elasticsearch-data` | Elasticsearch | All indexed documents |
| `postgresql-data` | PostgreSQL | Relational database files |
| `ollama-models` (external) | Ollama | Mistral 7B model weights (4.4 GB) |

> **Note on `zeek-spool`:** Zeek's `logs/current` is a symlink pointing to the absolute path `/usr/local/zeek/spool/zeek`. This volume must be mounted at the same path in both Zeek and Filebeat containers so the symlink resolves correctly from Filebeat.

---

## 6. Data Flow

```
[Attacker]
    │
    ├─SSH/Telnet──► Cowrie ──── cowrie.json ──────────────────────────┐
    ├─SMB/SQL/...─► Dionaea ─── dionaea.log ──────────────────────────┤
    ├─HTTP/HTTPS──► Galah ───── event_log.json ───────────────────────┤
    └─(all proto)─► Zeek ────── conn/ssh/http.log ───────────────────►│
                         (passive capture)                            │
                                                                      │
                                                              Filebeat (tail)
                                                                      │
                                                                      ▼
                                                              Logstash (filter)
                                                            ┌─────────────────┐
                                                            │ ECS rename      │
                                                            │ GeoIP enrich    │
                                                            │ Timestamp fix   │
                                                            │ Category tag    │
                                                            │ Debug drop      │
                                                            └────────┬────────┘
                                                                     │
                                                                     ▼
                                                           Elasticsearch
                                                      honeypot-logs-YYYY.MM.dd
```

---

## 7. Honeypot Design

### Cowrie — SSH/Telnet Deception
- **Persona:** `db-prod` running `SSH-2.0-OpenSSH_8.9p1`
- **Auth:** UserDB with 14 weak credentials (root, mongodb, dbadmin, ubuntu)
- **Captures:** login attempts, shell commands, file uploads/downloads (with SHA-256)
- **Output:** JSON per event (`cowrie.login.success`, `cowrie.command.input`, `cowrie.session.closed`, etc.)

### Dionaea — Multi-Protocol Malware Trap
- **Persona:** Windows Server 2019 (SMB), SQL Server 2019 (MSSQL)
- **Protocols:** 11 services — SMB 445, MSSQL 1433, MySQL 3306, HTTP 80, MQTT 1883, MongoDB 27017, Memcache 11211, PPTP 1723, FTP 23, HTTPS 443, RPC 135
- **Captures:** exploit attempts, malware binaries (stored in `dionaea-malware` volume)
- **SMB identity:** `WIN-SERVER2019` in `WORKGROUP`, shares `ADMIN$`, `C$`, `IPC$`

### Galah — LLM Web Deception
- **Ports:** 8080, 8888 (HTTP)
- **Backend:** Ollama + Mistral 7B via `http://forenhive-ollama:11434`
- **Behavior:** Generates realistic HTML responses matching the requested URL (login pages, admin panels, 404 pages, etc.)
- **Cache:** SQLite (`cache.db`) — repeated requests served instantly (~1s vs 40-80s for LLM)
- **Output:** JSON per HTTP request with full request/response metadata and source tag (`llm`/`cache`)

### Zeek — Passive Network Visibility
- **Mode:** `network_mode: host` with `NET_ADMIN` + `NET_RAW` capabilities
- **Interface:** `eno12399` (injected via `sed` on `node.cfg` at startup)
- **Logs:** `conn.log`, `ssh.log`, `http.log`, `dns.log`, `ssl.log`, `dhcp.log`
- **Output:** JSON format via `policy/tuning/json-logs`

---

## 8. Environment Variables

| Variable | Default | Used by |
|---|---|---|
| `POSTGRES_USER` | `forenhive` | PostgreSQL, Backend |
| `POSTGRES_PASSWORD` | *(required)* | PostgreSQL, Backend |
| `POSTGRES_DB` | `forenhive` | PostgreSQL, Backend |
| `ES_HOST` | `elasticsearch` | Backend |
| `ES_PORT` | `9200` | Backend |
| `OLLAMA_HOST` | `forenhive-ollama` | Galah |
| `OLLAMA_PORT` | `11434` | Galah |
| `OLLAMA_MODEL` | `mistral` | Galah |
| `SECRET_KEY` | *(required)* | Backend JWT |
| `ABUSEIPDB_API_KEY` | — | Sprint 3 enrichment |
| `VIRUSTOTAL_API_KEY` | — | Sprint 3 enrichment |

---

## 9. Sprint Roadmap

| Sprint | Scope | Status |
|---|---|---|
| Sprint 1 | Honeypots — Cowrie, Dionaea, Galah, Zeek | ✅ Complete |
| Sprint 2 | ETL Pipeline — Filebeat, Logstash, Elasticsearch | ✅ Complete |
| Sprint 3 | Forensic Engine — enrichment, YARA, MITRE, risk scoring, API, UI | 🔄 Planned |

---

## 10. Repository Structure

```
forenhive/
├── docker-compose.yml          # Full stack orchestration
├── .env                        # Runtime secrets (not committed)
├── .env.example                # Variable template
├── Makefile                    # up / down / logs / status / rebuild-galah
│
├── honeypots/
│   ├── cowrie/
│   │   ├── cowrie.cfg          # Hostname, auth class, SSH/Telnet config
│   │   └── userdb.txt          # Accepted credentials (14 entries)
│   ├── dionaea/
│   │   ├── smb.yaml            # Windows Server 2019 SMB identity
│   │   └── mssql.yaml          # SQL Server 2019 version string
│   ├── galah/galah-src/
│   │   ├── Dockerfile          # Multi-stage Go build → debian:bookworm-slim
│   │   ├── config/
│   │   │   ├── config.yaml     # LLM system prompt + ports
│   │   │   └── rules.yaml      # Static response rules (disabled)
│   │   └── cmd/ internal/ pkg/ # Go source code
│   └── zeek/
│       └── local.zeek          # Protocol modules + JSON output policy
│
├── pipeline/
│   ├── filebeat/
│   │   └── filebeat.yml        # 4 inputs, Logstash output
│   └── logstash/
│       ├── logstash.yml        # Workers, batch size
│       └── pipelines/
│           └── main.conf       # ECS normalization pipeline
│
└── docs/
    ├── architecture.md         # This file
    ├── sprint1_audit.md        # Sprint 1 audit report
    └── sprint2_audit.md        # Sprint 2 audit report
```
