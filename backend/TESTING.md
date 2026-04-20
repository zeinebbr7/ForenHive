# ForenHive Backend — Quick Test Guide

All examples assume the backend is reachable at `http://localhost:8000`
(inside Docker: `http://backend:8000`).

---

## 1. Unit tests

```bash
cd backend
pip install -r requirements.txt
pytest
```

Tests live in [tests/](tests/): risk scoring, alert dedup, STIX bundle
shape, JWT sign/verify, password hashing.

---

## 2. Health & auth

```bash
curl -s http://localhost:8000/health | jq

# Login (bootstrap admin from .env)
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'username=admin@forenhive.local&password=ChangeMe!2026' | jq -r .access_token)

curl -s http://localhost:8000/api/auth/me -H "Authorization: Bearer $TOKEN" | jq

# Create an analyst
curl -s -X POST http://localhost:8000/api/auth/users \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"email":"zeineb@forenhive.local","password":"Zeineb!2026","role":"analyst"}' | jq

# Refresh
curl -s -X POST http://localhost:8000/api/auth/refresh \
  -H 'Content-Type: application/json' \
  -d '{"refresh_token":"<REFRESH_TOKEN>"}' | jq
```

> All `/api/*` routes except `/api/auth/*` require `Authorization: Bearer $TOKEN`.
> For local dev, set `DISABLE_AUTH=true` in `.env` to skip auth.

---

## 3. Attacks

```bash
H="Authorization: Bearer $TOKEN"
curl -s -H "$H" "http://localhost:8000/api/attacks?honeypot=cowrie&country=FR&page=1&page_size=20" | jq
curl -s -H "$H" "http://localhost:8000/api/attacks/stats/hourly?hours=24" | jq
curl -N -H "$H" http://localhost:8000/api/attacks/stats/live
```

## 4. Sessions

```bash
curl -s -H "$H" "http://localhost:8000/api/sessions?active_only=true&limit=50" | jq
curl -s -H "$H" http://localhost:8000/api/sessions/<session_id> | jq
curl -s -X DELETE -H "$H" http://localhost:8000/api/sessions/<session_id> -i
```

## 5. Geo

```bash
curl -s -H "$H" "http://localhost:8000/api/geo/breakdown?top=15" | jq
curl -s -H "$H" http://localhost:8000/api/geo/honeypot-split | jq
```

## 6. Alerts

```bash
curl -s -H "$H" http://localhost:8000/api/alerts/config | jq
curl -s -X PUT -H "$H" -H 'Content-Type: application/json' \
  -d '{"threshold":80,"recipients":["soc@example.com"],"triggers":["high_severity","malware_detected"]}' \
  http://localhost:8000/api/alerts/config | jq
curl -s -X POST -H "$H" http://localhost:8000/api/alerts/test | jq
curl -s -H "$H" "http://localhost:8000/api/alerts/history?limit=25" | jq
```

The **alert watcher** runs automatically in the background (every
`ALERT_WATCHER_INTERVAL_SECONDS`, default 15s) and fires alerts without
any external trigger.

## 7. Profiling

```bash
curl -s -H "$H" http://localhost:8000/api/profiling/203.0.113.5 | jq
```

## 8. Forensics (timeline + YARA)

```bash
# Multi-source timeline for one IP
curl -s -H "$H" "http://localhost:8000/api/forensics/timeline?ip=203.0.113.5&limit=500" | jq

# Single-session timeline
curl -s -H "$H" "http://localhost:8000/api/forensics/timeline?session_id=abc-123" | jq

# YARA scan of a single SHA-256 (proxied to forensic-engine sidecar)
curl -s -H "$H" http://localhost:8000/api/forensics/yara/<sha256> | jq

# YARA sweep of Dionaea captures
curl -s -H "$H" "http://localhost:8000/api/forensics/yara?limit=50" | jq
```

## 9. Reports

```bash
curl -s -X POST -H "$H" -H 'Content-Type: application/json' \
  -d '{"scope":"ip","ip":"203.0.113.5","include_stix":true,"analyst":"zeineb"}' \
  http://localhost:8000/api/reports/generate | jq

curl -s -H "$H" http://localhost:8000/api/reports | jq
curl -OJ -D - -H "$H" http://localhost:8000/api/reports/<id>/download
curl -s -X POST -H "$H" http://localhost:8000/api/reports/<id>/stix | jq
```

## 10. Audit log (admin only)

```bash
curl -s -H "$H" "http://localhost:8000/api/audit?limit=50" | jq
curl -s -H "$H" "http://localhost:8000/api/audit?action=auth.login" | jq
```

---

## Running locally without Docker

```bash
cd backend
cp .env.example .env
# edit PG_PASSWORD, SMTP_*, JWT_SECRET
python3.11 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

Requires a running PostgreSQL and Elasticsearch reachable at the hosts
defined in `.env`. For pure API testing without dependencies, set
`DISABLE_AUTH=true` and skip the DB (the app still starts; only auth
and audit routes degrade).
