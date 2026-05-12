# ForenHive — Sprint 4 Audit
**Backend API: FastAPI · JWT Auth · Alert Engine · Reports · Chain of Custody**
*Branch: zinoba | Date: 2026-05-12*

---

## 1. Architecture Overview

Sprint 4 implements the C4 layer — the FastAPI REST API that sits between the forensic engine (C3) and the future React frontend (C5). It exposes all forensic data collected in Sprints 1–3 through a secured, rate-limited HTTP API.

```
PostgreSQL  ──┐
              ├──► backend (FastAPI :8000) ──► React (C5, Sprint 5)
Elasticsearch ─┘        │
                         ├── forensic-engine (C3, triggered every 6h)
                         ├── Ollama / Groq   (AI chat + profiling)
                         └── FreeTSA         (RFC 3161 chain of custody)
```

**Stack:** FastAPI 0.115.6 · Uvicorn · SQLAlchemy 2.0 async · asyncpg · Elasticsearch-py 8.13.2 · APScheduler 3.10.4 · SlowAPI · PassLib + bcrypt + PyJWT · WeasyPrint · Jinja2 · rfc3161-client

---

## 2. Components Implemented

### 2.1 Application Entry Point (`main.py`)

FastAPI app with full lifespan management:

| Startup action | Details |
|---|---|
| PostgreSQL init | `init_db()` → SQLAlchemy `create_all` + admin user bootstrap |
| Elasticsearch | `ping()` + internal index bootstrap (`forenhive-alerts`, `forenhive-profiles`, `forenhive-reports`) |
| Alert watcher | Background async task, polls every 15 s |
| Forensic scheduler | APScheduler `BackgroundScheduler`, runs `forensic_runner.run_forensic_engine` every 6 h |

**Middleware stack:**
- `CORSMiddleware` — configurable origins via `CORS_ORIGINS` env var
- Custom `request_middleware` — injects `X-Request-ID`, logs all requests with duration, fire-and-forget audit records for mutating methods (`POST / PUT / PATCH / DELETE`)

**Error handling:** RFC 7807 `application/problem+json` for all HTTP errors and unhandled exceptions.

---

### 2.2 Configuration (`config.py`)

`pydantic-settings` `BaseSettings` — reads from `.env`, all values overridable via environment variables.

| Category | Key variables |
|---|---|
| App | `APP_ENV`, `APP_HOST`, `APP_PORT`, `LOG_LEVEL` |
| Auth | `JWT_SECRET`, `JWT_ACCESS_TTL_MINUTES=30`, `JWT_REFRESH_TTL_DAYS=7`, `BOOTSTRAP_ADMIN_EMAIL/PASSWORD`, `DISABLE_AUTH` |
| PostgreSQL | `PG_HOST`, `PG_PORT`, `PG_DB`, `PG_USER`, `PG_PASSWORD` |
| Elasticsearch | `ES_HOST`, per-honeypot index patterns, `ES_REQUEST_TIMEOUT=30` |
| AI | `GROQ_API_KEY`, `GROQ_MODEL=llama-3.3-70b-versatile`, `OLLAMA_HOST`, `OLLAMA_MODEL=mistral:7b`, `OLLAMA_TIMEOUT=30` |
| Alerts | `RISK_ALERT_THRESHOLD=75`, `ALERT_DEDUP_WINDOW_MINUTES=15`, `ALERT_WATCHER_INTERVAL_SECONDS=15`, `ALERT_RECIPIENTS` |
| SMTP | `SMTP_HOST/PORT/USER/PASSWORD/FROM`, `SMTP_STARTTLS` |
| External APIs | `ABUSEIPDB_API_KEY`, `VIRUSTOTAL_API_KEY`, `IPLOCATE_API_KEY` |
| Forensic engine | `FORENSIC_ENGINE_URL=http://forensic-engine:8001`, `FORENSIC_ENGINE_TIMEOUT=30` |
| TSA | `TSA_URL=https://freetsa.org/tsr`, `TSA_CERT_URL` |
| Rate limiting | `RATELIMIT_DEFAULT=200/minute`, `RATELIMIT_SENSITIVE=10/minute` |

---

### 2.3 Database Layer (`db.py`)

Async SQLAlchemy engine with connection pooling:
- Pool: `pool_size=10`, `max_overflow=10`, `pool_pre_ping=True`
- `session_scope()` context manager with automatic commit / rollback
- `init_db()` runs `Base.metadata.create_all` at startup

**SQLAlchemy models (`models_sql/`):**

| Model | Table | Columns |
|---|---|---|
| `User` | `users` | `id`, `email`, `hashed_password`, `role` (admin/analyst), `is_active`, `created_at` |
| `AuditLog` | `audit_logs` | `id`, `action`, `actor_email`, `method`, `path`, `status_code`, `ip`, `user_agent`, `ts` |

---

### 2.4 Authentication (`routers/auth.py` + `services/auth_service.py`)

**Endpoints:**

| Method | Path | Description |
|---|---|---|
| POST | `/api/auth/login` | OAuth2 password flow → `{access_token, refresh_token, token_type}` |
| POST | `/api/auth/refresh` | Refresh token → new access token |
| GET | `/api/auth/me` | Current user info |
| POST | `/api/auth/users` | Admin: create user (role=analyst/admin) |
| PUT | `/api/auth/users/{id}` | Admin: update user |
| DELETE | `/api/auth/users/{id}` | Admin: delete user |

**Security:**
- HS256 JWT, 30-min access token + 7-day refresh token
- Passwords hashed with bcrypt via `passlib`
- Bootstrap admin created at startup if `users` table is empty
- `DISABLE_AUTH=true` skips all bearer checks (dev mode only)

---

### 2.5 Attacks Router (`routers/attacks.py`)

Queries Elasticsearch `honeypot-logs-*` indices.

| Endpoint | Description |
|---|---|
| `GET /api/attacks` | Paginated attack list — filters: `honeypot`, `country`, `protocol`, `min_risk`, `page`, `page_size` |
| `GET /api/attacks/stats/hourly` | Hourly event counts for the last N hours |
| `GET /api/attacks/stats/live` | SSE stream — real-time attack events (Server-Sent Events) |

---

### 2.6 Sessions Router (`routers/sessions.py`)

| Endpoint | Description |
|---|---|
| `GET /api/sessions` | List sessions — filters: `active_only`, `honeypot`, `limit` |
| `GET /api/sessions/{session_id}` | Full session detail (commands, file hashes, geo, risk) |
| `DELETE /api/sessions/{session_id}` | Mark session as archived |

---

### 2.7 Geo Router (`routers/geo.py`)

| Endpoint | Description |
|---|---|
| `GET /api/geo/breakdown` | Top N countries by attack count |
| `GET /api/geo/honeypot-split` | Country breakdown per honeypot type |
| `GET /api/geo/map` | GeoJSON-ready attack origins for choropleth map |
| `GET /api/geo/timeline` | Attack volume by country over time |
| `GET /api/geo/top-ips` | Top attacking IPs with geo + risk data |

---

### 2.8 Alerts (`routers/alerts.py` + `services/alert_engine.py` + `services/alert_watcher.py`)

**Alert watcher** runs every 15 seconds as a background `asyncio` task. On each tick:
1. Queries recent Elasticsearch events (last `ALERT_DEDUP_WINDOW_MINUTES`)
2. Evaluates 8 built-in alert triggers via `alert_engine.py`
3. Deduplicates: same trigger + same IP → suppressed within the window
4. Fires SMTP email if new alert and recipients configured

**8 alert triggers:**

| Trigger | Condition |
|---|---|
| `high_severity` | Risk score ≥ `RISK_ALERT_THRESHOLD` (default 75) |
| `malware_detected` | YARA match or VirusTotal hit |
| `brute_force` | Failed auth count > 200 in window |
| `lateral_movement` | SMB + credential access on same IP |
| `tor_exit_node` | IPLocate `is_tor = true` |
| `high_risk_country` | Source country in HIGH_RISK_COUNTRIES set |
| `c2_ioc` | C2/exploit keywords in HTTP paths or commands |
| `cve_probe` | CVE-YYYY-NNNNN regex match in request data |

**Endpoints:**

| Endpoint | Description |
|---|---|
| `GET /api/alerts/config` | Get current alert configuration |
| `PUT /api/alerts/config` | Update threshold / recipients / triggers |
| `GET /api/alerts/list` | List recent alert records |
| `POST /api/alerts/test` | Fire a test alert to configured recipients |
| `POST /api/alerts/evaluate` | Manual trigger of alert evaluation |

---

### 2.9 Risk Score Router (`routers/risk_score.py`)

| Endpoint | Description |
|---|---|
| `GET /api/risk-score/{ip}` | Fetch stored risk score for an IP from PostgreSQL |
| `GET /api/risk-score/breakdown/{ip}` | 18-signal breakdown with per-signal points and text |
| `GET /api/risk-score/top` | Top N highest-risk IPs |
| `POST /api/risk-score/recalculate` | Trigger forensic engine re-score for an IP |

---

### 2.10 Forensics Router (`routers/forensics.py`)

| Endpoint | Description |
|---|---|
| `GET /api/forensics/sessions` | Forensic sessions from PostgreSQL (risk, MITRE, kill chain) |
| `GET /api/forensics/sessions/{session_id}` | Full forensic session with signal breakdown |
| `GET /api/forensics/yara` | File analysis results — YARA matches + VirusTotal |
| `GET /api/forensics/timeline` | Multi-source forensic timeline (ms precision) |
| `POST /api/forensics/run` | Trigger forensic engine run (admin only) |

---

### 2.11 Reports (`routers/reports.py` + `services/report_service.py`)

**Format support:** HTML (via Jinja2) + PDF (WeasyPrint).

**Report types:**

| Type | Content |
|---|---|
| `ip_report` | Single IP: risk score, MITRE techniques, kill chain, enrichment, YARA/VT results, chain of custody |
| `session_report` | Cowrie/Dionaea/Galah session: commands, timeline, forensic narrative |
| `daily_summary` | Aggregated daily statistics across all honeypots |
| `threat_intel` | Top IPs, IOC list, STIX bundle export |

**Chain of custody** — every generated report:
1. SHA-256 of the report content computed
2. RFC 3161 timestamp request sent to FreeTSA (`https://freetsa.org/tsr`)
3. TSA token stored as base64 in report metadata (`X-ForenHive-SHA256` response header)

**Endpoints:**

| Endpoint | Description |
|---|---|
| `POST /api/reports/generate` | Generate a new report (returns report ID) |
| `GET /api/reports` | List all stored reports |
| `GET /api/reports/{id}` | Download report (HTML or PDF via `Accept` header) |
| `GET /api/reports/{id}/custody` | Chain of custody record (SHA-256 + TSA token) |

---

### 2.12 Profiling Router (`routers/profiling.py` + `services/profiler.py`)

LLM-assisted attacker profiling using Ollama (Mistral 7B) or Groq (Llama-3.3-70B).

| Endpoint | Description |
|---|---|
| `GET /api/profiling/{ip}` | Get stored profile for an IP |
| `POST /api/profiling/generate` | Generate FBI-style attacker profile for an IP |
| `GET /api/profiling/top` | Top attacker profiles by risk score |

**`profiler.py` — `build_profile(ip)`:**
- Fetches session history, MITRE techniques, command history from ES + PostgreSQL
- Builds structured prompt for Mistral 7B / Groq
- Returns: `motivation`, `sophistication`, `attack_pattern`, `geographic_hypothesis`, `recommended_mitigations`

---

### 2.13 AI Chat (`routers/chat.py`)

SSE streaming chat endpoint using Groq `llama-3.3-70b-versatile` with forensic system prompt.

**System prompt identity:** HIVE — ForenHive forensic assistant. Applies FBI criminal profiling to cyber attackers, maps behavior to MITRE ATT&CK, references risk scores and session data.

**Endpoints:**

| Endpoint | Description |
|---|---|
| `POST /api/chat` | Streaming chat (SSE) — question + optional context (session_id, IP) |

**Fallback:** If Groq unreachable, falls back to local Ollama Mistral 7B.

---

### 2.14 Honeypots Router (`routers/honeypots.py`)

Admin-only. Queries Docker socket (via `docker` Python SDK) to report container status.

| Endpoint | Description |
|---|---|
| `GET /api/honeypots/status` | All 4 honeypot containers — running/stopped, uptime, log tail |
| `POST /api/honeypots/{name}/restart` | Restart a honeypot container (admin only) |

---

### 2.15 Audit Router (`routers/audit.py`)

Admin-only. Reads from the `audit_logs` PostgreSQL table.

| Endpoint | Description |
|---|---|
| `GET /api/audit` | Paginated audit log — filter by actor, action, date range |
| `GET /api/audit/export` | Export audit log as CSV |

---

### 2.16 Email Service (`services/email_service.py`)

Async SMTP via `smtplib` (run in thread executor to avoid blocking). Supports STARTTLS. Alert emails include:
- Trigger type, source IP, risk score, MITRE technique
- Link to the full report

---

### 2.17 Elasticsearch Service (`services/elasticsearch.py`)

Single `ElasticsearchService` singleton wrapping the `AsyncElasticsearch` client.

Key methods:

| Method | Description |
|---|---|
| `ping()` | Health check |
| `ensure_internal_indices()` | Creates `forenhive-alerts`, `forenhive-profiles`, `forenhive-reports` with mappings |
| `query_attacks(...)` | Paginated attack search with aggregations |
| `query_hourly_stats(hours)` | Date histogram aggregation |
| `query_geo_breakdown(top)` | Terms aggregation on `source.geo.country_iso_code` |
| `query_sessions(...)` | Session-level aggregations |
| `stream_live_events()` | Async generator for SSE stream |

---

## 3. File Structure

```
backend/
├── main.py                 ← FastAPI app, lifespan, middleware
├── config.py               ← pydantic-settings config
├── db.py                   ← async SQLAlchemy engine + session management
├── requirements.txt
├── Dockerfile
├── pytest.ini
├── TESTING.md
├── routers/
│   ├── auth.py             ← JWT login/refresh/user management
│   ├── attacks.py          ← ES attack queries + SSE live stream
│   ├── sessions.py         ← session CRUD
│   ├── geo.py              ← geographic breakdowns + map data
│   ├── alerts.py           ← alert config + manual trigger
│   ├── risk_score.py       ← per-IP risk score + breakdown
│   ├── forensics.py        ← forensic sessions, YARA, timeline
│   ├── reports.py          ← HTML/PDF report generation
│   ├── profiling.py        ← LLM attacker profiles
│   ├── chat.py             ← HIVE assistant (Groq SSE)
│   ├── honeypots.py        ← container status (admin)
│   └── audit.py            ← audit log (admin)
├── services/
│   ├── auth_service.py     ← JWT encode/decode, bcrypt, bootstrap admin
│   ├── elasticsearch.py    ← ES client singleton + all query helpers
│   ├── alert_engine.py     ← 8-trigger alert evaluator + dedup
│   ├── alert_watcher.py    ← async background polling loop
│   ├── audit_service.py    ← async fire-and-forget audit records
│   ├── chain_custody.py    ← SHA-256 + RFC 3161 TSA timestamping
│   ├── email_service.py    ← async SMTP alert emails
│   ├── enrichment.py       ← AbuseIPDB / IPLocate calls from backend
│   ├── forensic_runner.py  ← calls forensic-engine container via HTTP
│   ├── ollama_service.py   ← Ollama Mistral 7B client (LLM fallback)
│   ├── profiler.py         ← attacker profiling logic
│   ├── report_adapter.py   ← normalize risk data for report templates
│   ├── report_service.py   ← full report assembly + PDF generation
│   └── yara_client.py      ← calls forensic-engine YARA endpoint
├── models/
│   ├── attack.py           ← Pydantic models for attack responses
│   ├── session.py          ← session response models
│   ├── alert.py            ← alert config + record models
│   └── report.py           ← report request/response models
├── models_sql/
│   ├── user.py             ← SQLAlchemy User ORM model
│   └── audit.py            ← SQLAlchemy AuditLog ORM model
├── templates/              ← Jinja2 HTML report templates
└── tests/
    ├── test_risk_score.py  ← risk scoring unit tests
    ├── test_alert_dedup.py ← alert deduplication logic tests
    ├── test_auth.py        ← JWT sign/verify + password hashing
    └── test_stix.py        ← STIX bundle shape validation
```

---

## 4. Design Decisions

| Decision | Rationale |
|---|---|
| Single `ElasticsearchService` singleton | Avoids opening a new HTTP connection pool per request — Elasticsearch client is expensive to initialize |
| APScheduler for forensic engine (every 6 h) | Forensic engine is a separate container; backend triggers it via HTTP rather than running it in-process, keeping C3 and C4 independent |
| Alert watcher as `asyncio` background task | Purely I/O-bound polling loop; no thread needed — fits naturally in the FastAPI event loop |
| Groq primary + Ollama fallback for chat | Groq `llama-3.3-70b-versatile` is significantly faster than CPU-only Mistral 7B on the Dell R750 (no GPU). Ollama remains as offline fallback |
| RFC 3161 via FreeTSA | FreeTSA provides free trusted timestamps. Every report gets a cryptographic proof of existence that cannot be backdated — required for forensic chain of custody |
| RFC 7807 problem+json errors | Standard machine-readable error format; frontend can parse `type`, `title`, `detail` fields consistently without string-matching |
| `DISABLE_AUTH=true` for dev | Allows testing all endpoints without token management during local development |
| Audit fire-and-forget | Audit writes must never block or fail the primary request — wrapped in `try/except` and called without `await` blocking the response |

---

## 5. API Summary

| Category | Endpoints | Auth required |
|---|---|---|
| Auth | 6 | Login: public; others: bearer |
| Attacks | 3 | Yes |
| Sessions | 3 | Yes |
| Geo | 5 | Yes |
| Alerts | 5 | Yes |
| Risk Score | 4 | Yes |
| Forensics | 5 | Yes |
| Reports | 4 | Yes |
| Profiling | 3 | Yes |
| Chat | 1 | Token checked client-side |
| Honeypots | 2 | Admin only |
| Audit | 2 | Admin only |
| Health | 1 | Public |
| **Total** | **44** | |

---

## 6. Test Suite

| File | Tests | Covers |
|---|---|---|
| `test_risk_score.py` | Unit | 18-signal scorer: private IP bypass, score cap at 100, each signal bucket |
| `test_alert_dedup.py` | Unit | Deduplication window: same trigger+IP suppressed, different IP fires |
| `test_auth.py` | Unit | JWT encode/decode, expiry, bcrypt hash/verify |
| `test_stix.py` | Unit | STIX 2.1 bundle shape — required fields, relationship objects |

Run:
```bash
cd backend && pytest
```

---

## 7. Known Limitations

| Item | Description | Impact |
|---|---|---|
| FreeTSA availability | RFC 3161 TSA request is synchronous and blocks report generation (~300ms). FreeTSA may be unavailable | `chain_custody.py` catches exceptions and stores `tsa_token_b64=None` — report still generated |
| Groq rate limit | Free tier: 6000 tokens/minute. Heavy chat use can hit the limit | Fallback to Ollama adds ~30–60s latency per message |
| Docker socket in honeypots router | `honeypots.py` mounts `/var/run/docker.sock` — security tradeoff for admin container restart | Admin-only guard; acceptable for internal dev server |
| No WebSocket | Live attack stream uses SSE (Server-Sent Events), not WebSockets | SSE is unidirectional — sufficient for dashboard feed, not for bidirectional chat |
| Report PDF memory | WeasyPrint renders PDF in-process — large reports (1000+ events) may consume >500 MB RAM | Paginate report data before passing to template |
| Frontend not yet connected | React frontend (C5) is not implemented — backend tested via curl / TESTING.md | All API endpoints functional; UI is Sprint 5 |

---

## 8. Sprint 4 Status

| Component | File(s) | Status |
|---|---|---|
| FastAPI app + middleware | `main.py` | ✅ Complete |
| Configuration | `config.py` | ✅ Complete |
| Async PostgreSQL layer | `db.py`, `models_sql/` | ✅ Complete |
| JWT authentication | `routers/auth.py`, `services/auth_service.py` | ✅ Complete |
| Attacks API | `routers/attacks.py` | ✅ Complete |
| Sessions API | `routers/sessions.py` | ✅ Complete |
| Geo API | `routers/geo.py` | ✅ Complete |
| Alert engine + watcher | `services/alert_engine.py`, `services/alert_watcher.py` | ✅ Complete |
| Alerts API | `routers/alerts.py` | ✅ Complete |
| Risk score API | `routers/risk_score.py` | ✅ Complete |
| Forensics API | `routers/forensics.py` | ✅ Complete |
| Report generation (HTML + PDF) | `routers/reports.py`, `services/report_service.py` | ✅ Complete |
| RFC 3161 chain of custody | `services/chain_custody.py` | ✅ Complete |
| Attacker profiling | `routers/profiling.py`, `services/profiler.py` | ✅ Complete |
| AI chat (HIVE) | `routers/chat.py`, `services/ollama_service.py` | ✅ Complete |
| Honeypots admin | `routers/honeypots.py` | ✅ Complete |
| Audit log | `routers/audit.py`, `services/audit_service.py` | ✅ Complete |
| Email alerts | `services/email_service.py` | ✅ Complete |
| Unit tests (4 files) | `tests/` | ✅ Complete |
| React frontend (C5) | `frontend/` | 🔲 Sprint 5 |
