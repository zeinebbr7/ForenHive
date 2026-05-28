# Sprint 4 — Backend FastAPI

## Sprint Overview

- **Sprint name:** Backend FastAPI
- **Sprint number:** 4
- **Goal:** Expose every artefact produced by Sprints 1–3 (honeypot events, sessions, IoCs, profiles, risk scores, chain of custody) behind a single authenticated REST API the SPA can consume.

## Objectives

- Build a single FastAPI service (`forenhive-backend`, port 8000) fronting Elasticsearch + PostgreSQL + Ollama.
- Enforce JWT bearer auth with role-based protection for admin-only routes.
- Provide an in-process alert engine with multi-channel fan-out (email, SMS, WhatsApp).
- Render bilingual (EN/FR) PDF reports via Jinja2 + WeasyPrint.
- Keep routers thin — push every external integration into a `services/` layer.

## Tasks Completed

- **13 routers** covering auth, sessions, attacks, geo, alerts, profiling, forensics, risk score, reports, honeypots, audit, chat (HIVE), and health-style checks.
- **JWT bearer auth** (PyJWT). SPA stores the token in `localStorage` under `forenhive.token`. Role checks gate `admin`-only routes.
- **Service layer** wrapping Elasticsearch, PostgreSQL, Ollama, Twilio (SMS/WhatsApp), SMTP, the forensic engine's runner, YARA, and the audit log.
- **Alert engine + watcher** running in-process: polls new sessions / high-risk scores, fans out to email and Twilio with rate-limited templates.
- **Report pipeline** — Jinja2 with `StrictUndefined` rendering `forenhive_rapport_v2*.html` to a WeasyPrint PDF (EN + FR).
- **Audit log** — every mutating router writes through `audit_service`.

## Technical Details

- App built from [`backend/Dockerfile`](../../backend/Dockerfile) on top of `python:3.12-slim` with WeasyPrint system deps.
- [`backend/main.py`](../../backend/main.py) wires CORS, mounts the 13 routers, registers lifespan hooks (alert watcher startup, DB pool shutdown), and exposes `/health`.
- DB access is async SQLAlchemy 2.0 + asyncpg ([`backend/db.py`](../../backend/db.py)) — one engine, dependency-injected sessions per request.
- Config goes through `pydantic-settings` ([`backend/config.py`](../../backend/config.py)) — `.env` is the single source of truth for secrets and toggles.
- Forensic-engine tables are **read-only** from the backend's perspective; only `users` and `audit` are owned here.
- API contract documented at [docs/api.md](../api.md).

### Routers (`backend/routers/`)

| File | Responsibility |
|------|----------------|
| [`auth.py`](../../backend/routers/auth.py) | login, logout, refresh, password change. Issues JWT. |
| [`sessions.py`](../../backend/routers/sessions.py) | list/search forensic sessions, fetch one with timeline + IoCs. |
| [`attacks.py`](../../backend/routers/attacks.py) | aggregated honeypot events for the dashboard. |
| [`geo.py`](../../backend/routers/geo.py) | country / ASN aggregations for the GeoMap. |
| [`alerts.py`](../../backend/routers/alerts.py) | list, ack, suppress alerts; trigger test send. |
| [`profiling.py`](../../backend/routers/profiling.py) | suspect-profile CRUD + filters. |
| [`forensics.py`](../../backend/routers/forensics.py) | on-demand re-run of the engine, evidence packaging. |
| [`risk_score.py`](../../backend/routers/risk_score.py) | per-IP risk lookups (table `ip_risk_scores`). |
| [`reports.py`](../../backend/routers/reports.py) | build bilingual context, render PDF via WeasyPrint. |
| [`honeypots.py`](../../backend/routers/honeypots.py) | per-honeypot status, raw log slice, config peek (admin). |
| [`audit.py`](../../backend/routers/audit.py) | append-only audit-log viewer. |
| [`chat.py`](../../backend/routers/chat.py) | HIVE assistant — proxies the SPA chat to the LLM. |

### Domain models

- `backend/models/` — Pydantic schemas exchanged with the SPA: [`session.py`](../../backend/models/session.py), [`attack.py`](../../backend/models/attack.py), [`alert.py`](../../backend/models/alert.py), [`report.py`](../../backend/models/report.py).
- `backend/models_sql/` — SQLAlchemy models for tables owned by the backend: [`user.py`](../../backend/models_sql/user.py) (auth users + roles), [`audit.py`](../../backend/models_sql/audit.py) (audit-log entries).

### Services (`backend/services/`)

- [`elasticsearch.py`](../../backend/services/elasticsearch.py) — async ES client used by sessions/attacks/geo.
- [`ollama_service.py`](../../backend/services/ollama_service.py) — chat + embedding calls used by `/chat` and profiler re-runs.
- [`yara_client.py`](../../backend/services/yara_client.py) — talks to the forensic-engine YARA module on demand.
- [`forensic_runner.py`](../../backend/services/forensic_runner.py) — triggers an out-of-cycle engine pass for a single session.
- [`enrichment.py`](../../backend/services/enrichment.py) — thin proxy over the engine's enricher.
- [`profiler.py`](../../backend/services/profiler.py) — server-side helpers (filtering, sorting, ViCAP joins).
- [`chain_custody.py`](../../backend/services/chain_custody.py) — read side of the CoC tables; display-ready validation status.
- [`quota_tracker.py`](../../backend/services/quota_tracker.py) — backend-side daily API counters.
- [`audit_service.py`](../../backend/services/audit_service.py) — write helper called by every mutating router.
- [`auth_service.py`](../../backend/services/auth_service.py) — bcrypt (passlib), JWT issuance/validation, role checks.
- [`email_service.py`](../../backend/services/email_service.py) — SMTP send with Jinja HTML/text alternatives.
- [`alert_engine.py`](../../backend/services/alert_engine.py) — threshold + dedup logic.
- [`alert_watcher.py`](../../backend/services/alert_watcher.py) — background loop started at lifespan.
- [`report_service.py`](../../backend/services/report_service.py) — Jinja2 + WeasyPrint wrapper.
- [`report_adapter.py`](../../backend/services/report_adapter.py) — converts engine data shape into template variables.

### Alerts package

- [`backend/alerts/alert_manager.py`](../../backend/alerts/alert_manager.py) — multi-channel fan-out (email + Twilio SMS + WhatsApp) with per-channel retry and rate-limit policy.

### Templates

- [`templates/forenhive_rapport_v2.html`](../../backend/templates/forenhive_rapport_v2.html) — main English PDF template.
- [`templates/forenhive_rapport_v2_fr.html`](../../backend/templates/forenhive_rapport_v2_fr.html) — French counterpart.
- [`templates/report.html`](../../backend/templates/report.html) — legacy short-summary fallback.
- [`templates/alert_email.html`](../../backend/templates/alert_email.html) — HTML body for `email_service`.

### Tests

- [`tests/test_risk_score_integration.py`](../../backend/tests/test_risk_score_integration.py) — end-to-end check that the engine's score table is reachable and serialised correctly through `/api/risk-score`.

## Challenges & Solutions

- **Silent missing data in PDF reports** — `StrictUndefined` is used in Jinja2 so any missing context key raises a 500 instead of silently rendering a blank cell. Protects the operator from undetected data loss.
- **Multi-channel alerting reliability** — `alert_manager` applies per-channel retry and rate-limit policies, so a Twilio outage cannot block email and vice versa.
- **Thin routers / heavy integrations** — every external system (ES, PG, Ollama, SMTP, Twilio, YARA, engine runner) is wrapped in a `services/` adapter so routers stay HTTP-only and testable.
- **Mixed table ownership** — backend owns only `users` and `audit`; all forensic-engine tables are read-only to prevent the API from corrupting evidence.

## Outcomes / Deliverables

- Authenticated REST API on `:8000` with 13 routers and an interactive OpenAPI doc.
- Working bilingual PDF report pipeline.
- Live alert watcher dispatching to email + SMS + WhatsApp.
- Validation gates passed:
  1. `POST /api/auth/login` with seeded creds returns a usable JWT.
  2. Every router responds 200 on its `GET /` happy path with a valid token.
  3. `POST /api/reports/{session_id}` returns a non-empty PDF (EN and FR).
  4. An induced high-risk session triggers a real alert (verified in `mailhog` / Twilio sandbox).
  5. `pytest backend/tests/` green.

## Notes / Next Steps

- The API is operator-ready but headless. Sprint 5 builds the React SPA that consumes it.
- Report rendering is owned here; the SPA only triggers it and streams the result back as a download.
