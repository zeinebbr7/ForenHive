# ForenHive — Operations Command Reference

Every docker, docker compose, script, test, and inspection command for running, testing,
and getting to know ForenHive. Each block notes the **directory to run it from**.

Unless stated otherwise, run from the project root: `/home/pfe/forenhive`.

---

## 1. Quick start

```bash
# from: /home/pfe/forenhive
make up          # start every service in the background
make status      # see what's running
make logs        # tail all logs (Ctrl-C to stop tailing)
make down        # stop and remove all containers
```

First-time setup also needs the env file and the DB schema:

```bash
# from: /home/pfe/forenhive
cp .env.example .env          # then edit secrets (JWT_SECRET, POSTGRES_PASSWORD, API keys)
make up
docker compose exec forensic-engine python db/init_db.py   # create PostgreSQL schema
```

---

## 2. Service & container reference

Use the **service** name with `docker compose`, the **container** name with raw `docker`.

| Service (compose)    | Container             | Port(s)                        | Role                                  |
|----------------------|-----------------------|--------------------------------|---------------------------------------|
| `cowrie`             | `forenhive-cowrie`    | 2222 (SSH), 2223 (Telnet)      | SSH/Telnet honeypot                   |
| `dionaea`            | `forenhive-dionaea`   | 23/80/135/443/445/1433/1723/1883/3306/11211/27017 | Multi-protocol malware honeypot |
| `galah`              | `forenhive-galah`     | 8080, 8888                     | LLM web honeypot                      |
| `zeek`               | `forenhive-zeek`      | host network (no mapped ports) | Passive network analyzer / NIDS       |
| `filebeat`           | `forenhive-filebeat`  | —                              | Log tailer → Logstash:5044            |
| `logstash`           | `forenhive-logstash`  | 5044 (beats)                   | ECS normalization, GeoIP, IP mapping  |
| `elasticsearch`      | `forenhive-elasticsearch` | 127.0.0.1:9200             | Log store (`honeypot-logs-YYYY.MM.dd`)|
| `postgresql`         | `forenhive-postgresql`| 5432 (internal)                | Auth / audit / forensic results       |
| `forensic-engine`    | `forenhive-forensic-engine` | 8001                     | Forensic analysis CLI + HTTP sidecar  |
| `forenhive-backend`  | `forenhive-backend`   | 8000                           | FastAPI REST API (JWT)                |
| `ollama`             | `forenhive-ollama`    | 11434 (internal)               | Mistral 7B (profiling, MITRE, galah)  |
| `forenhive-frontend` | `forenhive-frontend`  | 3000                           | React dashboard (nginx)               |

---

## 3. Docker Compose

```bash
# from: /home/pfe/forenhive

# Lifecycle
docker compose up -d                       # start all (detached)
docker compose up -d <service>             # start one service
docker compose down                        # stop + remove containers (volumes kept)
docker compose down -v                     # ⚠ also remove named volumes (destroys data)
docker compose restart <service>           # restart one service
docker compose stop <service>              # stop without removing

# Status
docker compose ps                          # running services
docker compose ps -a                       # include stopped

# Build / refresh images
docker compose build <service>             # rebuild one image
docker compose build                       # rebuild all
docker compose up -d --force-recreate <service>     # recreate container from current image
docker compose up -d --build <service>     # rebuild image AND recreate container
docker compose pull                        # pull updated base images
```

**Backend rebuild rule:** backend Python is baked into the image. After editing
`backend/**/*.py`, you MUST rebuild — a plain `restart` keeps the old code:

```bash
docker compose up -d --build forenhive-backend
```

The same applies to `forensic-engine` and `forenhive-frontend` (their code is in the image).

---

## 4. Makefile shortcuts

```bash
# from: /home/pfe/forenhive
make up             # docker compose up -d
make down           # docker compose down
make restart        # docker compose restart
make logs           # docker compose logs -f
make status         # docker compose ps
make ps             # docker compose ps -a
make rebuild-galah  # docker compose build galah && docker compose up -d --force-recreate galah
```

---

## 5. Logs & inspection

```bash
# from: /home/pfe/forenhive

# Logs
docker compose logs -f <service>                 # follow one service
docker compose logs -f --tail=100 <service>      # last 100 lines, then follow
docker compose logs --since=10m <service>        # last 10 minutes
docker logs -f forenhive-backend                 # raw docker (by container name)

# Resource usage
docker stats                                     # live CPU/mem per container
docker compose top                               # processes per service

# Shell into a container
docker compose exec forenhive-backend bash
docker compose exec forensic-engine bash

# PostgreSQL shell
docker compose exec postgresql psql -U forenhive -d forenhive

# Ollama: list loaded models
docker compose exec ollama ollama list
curl -s http://localhost:11434/api/tags | jq .   # (only if 11434 is reachable from host)
```

---

## 6. Forensic engine CLI

The engine runs every module by default, or one stage at a time with a `--*-only` flag.
Run it inside the container (recommended — has all deps + network):

```bash
# from: /home/pfe/forenhive  (via the running container)
docker compose exec forensic-engine python engine.py                 # full run, last 24h
docker compose exec forensic-engine python engine.py --hours 48      # custom lookback window

# Single-stage runs
docker compose exec forensic-engine python engine.py --enrich-only   # IP enrichment + GeoIP
docker compose exec forensic-engine python engine.py --yara-only     # YARA scan on Dionaea payloads
docker compose exec forensic-engine python engine.py --smb-only      # SMB forensic analysis
docker compose exec forensic-engine python engine.py --timeline-only # build per-IP timeline
docker compose exec forensic-engine python engine.py --ioc-only      # extract IoCs from timeline
docker compose exec forensic-engine python engine.py --score-only    # risk scoring + MITRE ATT&CK
docker compose exec forensic-engine python engine.py --profile-only  # LLM profiling (high-risk IPs)
docker compose exec forensic-engine python engine.py --coc-only      # seal chain of custody

# Database / quota admin
docker compose exec forensic-engine python engine.py --init-db                  # init PG schema
docker compose exec forensic-engine python engine.py --quota-status             # print API quotas
docker compose exec forensic-engine python engine.py --quota-reset virustotal   # clear exhausted flag
#   --quota-reset accepts: virustotal | abuseipdb | iplocate | shodan
```

Run locally instead (needs Python deps installed and reachable PG/ES/Ollama):

```bash
# from: /home/pfe/forenhive/forensic-engine
pip install -r requirements.txt
python engine.py --hours 24
```

The HTTP sidecar (`server.py`, port 8001) starts automatically via the container CMD and
re-runs `engine.py` every `ENGINE_INTERVAL_MINUTES`.

---

## 7. Database (PostgreSQL)

```bash
# from: /home/pfe/forenhive

# Create / re-apply schema (forensic-engine/db/schema.sql)
docker compose exec forensic-engine python db/init_db.py
#   reads PG_HOST / PG_PORT / PG_DB / PG_USER / PG_PASSWORD (defaults: db=forenhive, user=forenhive)

# Interactive shell
docker compose exec postgresql psql -U forenhive -d forenhive

# Quick inspection queries
docker compose exec postgresql psql -U forenhive -d forenhive -c "\dt"
docker compose exec postgresql psql -U forenhive -d forenhive -c "SELECT count(*) FROM forensic_sessions;"
docker compose exec postgresql psql -U forenhive -d forenhive -c "SELECT source_ip, risk_score FROM forensic_sessions ORDER BY risk_score DESC LIMIT 10;"
docker compose exec postgresql psql -U forenhive -d forenhive -c "SELECT * FROM api_quota_status;"
docker compose exec postgresql psql -U forenhive -d forenhive -c "SELECT email, role FROM users;"
```

Key tables: `forensic_sessions`, `forensic_timeline_events`, `forensic_iocs`,
`forensic_chain_of_custody`, `file_analysis`, `ip_enrichment_cache`, `suspect_profiles`,
`api_quota_status`, `users`, `audit_log`.

---

## 8. Pipeline / ETL (Filebeat → Logstash → Elasticsearch)

Flow: honeypots write logs → **Filebeat** tails them → ships to **Logstash:5044** →
Logstash maps IPs (`ip_map.yml`), adds GeoIP, normalizes to ECS → **Elasticsearch**
daily index `honeypot-logs-YYYY.MM.dd`.

```bash
# from: /home/pfe/forenhive

# Watch the pipeline
docker compose logs -f filebeat
docker compose logs -f logstash

# ip_map.yml hot-reloads every 60s — just edit and wait (no restart needed):
#   pipeline/logstash/config/ip_map.yml   (internal Docker IP -> public attacker IP)
# To force it immediately:
docker compose restart logstash

# Inspect Elasticsearch indices / docs
curl -s 'http://localhost:9200/_cat/indices/honeypot-logs-*?v'
curl -s 'http://localhost:9200/honeypot-logs-*/_count' | jq .
curl -s 'http://localhost:9200/honeypot-logs-*/_search?size=1&pretty'
```

---

## 9. Tests

```bash
# from: /home/pfe/forenhive
pytest                                                  # all tests
pytest -q                                               # quiet
pytest -v                                               # verbose
pytest -k reputation                                    # filter by name

# Per-suite
pytest forensic-engine/tests/test_risk_score.py        # engine unit tests (risk model)
pytest backend/tests/test_risk_score_integration.py    # backend integration tests
```

`forensic-engine/tests/conftest.py` fixes up `sys.path` so the flat engine modules import.

---

## 10. Frontend

```bash
# from: /home/pfe/forenhive/frontend
npm install            # first time only
npm run dev            # Vite dev server on :5173 (proxies /api -> :8000)
npm run build          # production bundle -> frontend/dist/
npm run preview        # serve the built bundle locally

# Build/ship the containerized (nginx) frontend instead:
# from: /home/pfe/forenhive
docker compose up -d --build forenhive-frontend         # served on :3000
```

---

## 11. Health checks (curl)

```bash
curl -fsS http://localhost:8000/health             # backend (FastAPI)        -> {"status":"ok"}
curl -fsS http://localhost:8001/health             # forensic-engine sidecar
curl -fsS http://localhost:9200/_cluster/health    # elasticsearch
curl -s   http://localhost:11434/api/tags          # ollama (if reachable from host)

# "Are the core services up?" one-liner
for u in localhost:8000/health localhost:8001/health localhost:9200/_cluster/health; do
  printf '%s -> ' "$u"; curl -fsS "http://$u" >/dev/null && echo OK || echo DOWN
done
```

---

## 12. Test-traffic generation

`scripts/dos_burst.sh` fires a bounded HTTP burst at a honeypot. The source IP is mapped
to `185.220.101.5` (Tor exit, "expert attacker") by the Logstash `translate` filter, so
the traffic shows up attributed to the demo's expert attacker on the dashboard.

```bash
# from: /home/pfe/forenhive
./scripts/dos_burst.sh                              # default: http://localhost:80/index.html, 60s, 50 workers
./scripts/dos_burst.sh http://localhost:80 30       # explicit URL, 30s
./scripts/dos_burst.sh http://localhost:80 60 100   # 60s, 100 concurrent workers
```

Uses Apache Bench (`ab`) if installed, else a parallel `curl` loop. For real rate control:
`sudo apt-get install -y apache2-utils`. Note: Zeek (host network) won't see localhost traffic.

---

## 13. Common recovery

```bash
# from: /home/pfe/forenhive

# Dionaea log stops writing after ~424 MB -> restart it
docker compose restart dionaea

# Service stuck / config changed -> recreate from current image
docker compose up -d --force-recreate <service>

# Backend serving stale code -> rebuild image (restart is not enough)
docker compose up -d --build forenhive-backend

# Reclaim disk from old images/layers
docker image prune -f
docker system df                                   # see what's using space

# Full reset of one service's state (⚠ destroys that volume's data)
docker compose stop <service> && docker compose rm -f <service>
```
