# ForenHive Backend — Quick Test Guide

All examples assume the backend is reachable at `http://localhost:8000`
(inside Docker: `http://backend:8000`).

## Health

```bash
curl -s http://localhost:8000/health | jq
```

## /api/attacks

```bash
# List (page 1, 20/page, filter by SSH honeypot + FR)
curl -s "http://localhost:8000/api/attacks?honeypot=cowrie&country=FR&page=1&page_size=20" | jq

# Single event
curl -s http://localhost:8000/api/attacks/<event_id> | jq

# Hourly bar chart (24h window)
curl -s "http://localhost:8000/api/attacks/stats/hourly?hours=24" | jq

# Live SSE stream (Ctrl-C to stop)
curl -N http://localhost:8000/api/attacks/stats/live
```

## /api/sessions

```bash
# Active sessions only
curl -s "http://localhost:8000/api/sessions?active_only=true&limit=50" | jq

# Session detail
curl -s http://localhost:8000/api/sessions/<session_id> | jq

# Force close
curl -s -X DELETE http://localhost:8000/api/sessions/<session_id> -i
```

## /api/geo

```bash
curl -s "http://localhost:8000/api/geo/breakdown?top=15" | jq
curl -s http://localhost:8000/api/geo/honeypot-split | jq
```

## /api/alerts

```bash
# Current config
curl -s http://localhost:8000/api/alerts/config | jq

# Update config
curl -s -X PUT http://localhost:8000/api/alerts/config \
  -H 'Content-Type: application/json' \
  -d '{"threshold":80,"recipients":["soc@example.com"],"triggers":["high_severity","malware_detected"]}' | jq

# Send self-test email
curl -s -X POST http://localhost:8000/api/alerts/test | jq

# History
curl -s "http://localhost:8000/api/alerts/history?limit=25" | jq

# Internal hook used by forensic-engine / ETL
curl -s -X POST http://localhost:8000/api/alerts/evaluate \
  -H 'Content-Type: application/json' \
  -d '{"source_ip":"203.0.113.5","severity":"high","threat_type":"ssh_bruteforce",
       "honeypot":"cowrie","failed_auth_count":42,"country_iso":"CN",
       "mitre_techniques":["T1110"],"commands":["cat /etc/shadow","wget http://x/c2"]}'
```

## /api/profiling

```bash
curl -s http://localhost:8000/api/profiling/203.0.113.5 | jq
```

## /api/reports

```bash
# Generate PDF for an IP (with STIX bundle)
curl -s -X POST http://localhost:8000/api/reports/generate \
  -H 'Content-Type: application/json' \
  -d '{"scope":"ip","ip":"203.0.113.5","include_stix":true,"analyst":"zeineb"}' | jq

# List generated reports
curl -s http://localhost:8000/api/reports | jq

# Download PDF (sha256 is returned in X-ForenHive-SHA256 header)
curl -OJ -D - http://localhost:8000/api/reports/<id>/download

# STIX 2.1 bundle
curl -s -X POST http://localhost:8000/api/reports/<id>/stix | jq
```

## Running locally without Docker

```bash
cd backend
cp .env.example .env
python3.11 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```
