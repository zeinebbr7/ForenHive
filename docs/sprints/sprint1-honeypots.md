# Sprint 1 — Honeypots

## Sprint Overview

- **Sprint name:** Honeypots
- **Sprint number:** 1
- **Goal:** Deploy a multi-protocol honeypot layer that lures attackers across SSH, SMB, HTTP, and passive network traffic, while staying strictly isolated from the rest of the ForenHive platform.

## Objectives

- Stand up three complementary honeypots  + zeek covering distinct attack surfaces (interactive shell, vulnerable services, web, passive capture).
- Guarantee network isolation between the honeypots and the production backend.
- Emit structured (JSON) logs into a shared volume so the Sprint 2 pipeline can ingest them without extra glue.
- Make every honeypot's configuration versioned in git for reproducibility.

## Tasks Completed

- **Cowrie (SSH/Telnet honeypot)** — simulates SSH on 2222 and Telnet on 2223, captures brute-force credentials, full shell sessions, downloaded payloads, and serves a fake filesystem.
- **Dionaea (multi-service honeypot)** — exposes 11 protocols (SMB, MSSQL, HTTP, MQTT, MySQL, FTP, …) to catch worm-style exploits (EternalBlue probes, MSSQL logins, malware uploads).
- **Galah (LLM-backed HTTP honeypot)** — uses Mistral 7B via Ollama to generate plausible HTTP responses for arbitrary paths, keeping scanners engaged instead of bailing on a 404.
- **Zeek (passive packet capture)** — runs in host network mode on the production NIC (`eno12399`), producing ground-truth `conn.log`, `http.log`, `dns.log`, etc.
- **Shared log volume** wired into all four containers so Filebeat (Sprint 2) has a single tail target.
- **Dedicated Docker network** `honeypot-net` with no route to `backend-net`.

## Technical Details

- All wiring lives in [docker-compose.yml](../../docker-compose.yml) — services `cowrie`, `dionaea`, `galah`, `zeek`.
- Cowrie and Dionaea use upstream Docker images (`cowrie/cowrie`, `dinotools/dionaea`) with bind-mounted configs.
- Galah is **built from vendored source** under [honeypots/galah/galah-src/](../../honeypots/galah/galah-src/) so the LLM-prompting layer can be patched.
- Zeek runs with `network_mode: host` and Linux `NET_ADMIN` / `NET_RAW` capabilities — required for raw packet sniffing.

### Per-honeypot file map

**`honeypots/cowrie/`**
- [`cowrie.cfg`](../../honeypots/cowrie/cowrie.cfg) — SSH on 2222, Telnet on 2223, JSON output, honeytoken files, fake hostname/banner.
- [`userdb.txt`](../../honeypots/cowrie/userdb.txt) — accepted weak passwords (`root:0:0`, `admin:1:1`, …) so attackers "get in" and start typing commands.

**`honeypots/dionaea/`**
- [`dionaea.cfg`](../../honeypots/dionaea/dionaea.cfg) — master config (services, log destinations, incident handlers).
- [`smb.yaml`](../../honeypots/dionaea/smb.yaml) — SMB shares, NTLM challenge behaviour, upload sinkhole.
- [`mssql.yaml`](../../honeypots/dionaea/mssql.yaml) — server version string, accepted auth modes.
- [`docker-compose.dionaea.yml`](../../honeypots/dionaea/docker-compose.dionaea.yml) — standalone bring-up reference (production wiring is in the root compose).

**`honeypots/galah/galah-src/`** (vendored Go source, MIT)
- `cmd/galah/main.go` — binary entry point.
- `internal/server/server.go` — HTTP listeners on 8080/8888.
- `pkg/llm/ollama.go` — Ollama client calling Mistral 7B.
- `config/config.yaml` — provider, model, ports, log paths.
- `config/rules.yaml` — Suricata-style match rules applied before the LLM is invoked.

**`honeypots/zeek/`**
- [`local.zeek`](../../honeypots/zeek/local.zeek) — site-local policy: loads protocol analyzers, enables JSON logs, filters the honeypot interface.

## Challenges & Solutions

- **Galah upstream churn** — to avoid breakage from upstream changes and keep the LLM-prompting code patchable, the project vendors Galah's Go source instead of using a published image.
- **Zeek vs. Docker networking** — bridge networking strips visibility into real host traffic, so Zeek had to run with `network_mode: host` and elevated `NET_ADMIN` / `NET_RAW` capabilities.
- **Risk of honeypots reaching production** — mitigated by placing all four containers on a dedicated `honeypot-net` with no route to `forenhive-backend`, verified during validation.

## Outcomes / Deliverables

- Four healthy honeypot containers (`cowrie`, `dionaea`, `galah`, `zeek`) emitting structured JSON to a shared volume.
- Isolation contract: no honeypot can reach `forenhive-backend` (verified by `docker compose exec cowrie nc -zv forenhive-backend 8000` failing).
- Validation gates passed:
  1. Each container is `healthy` in `docker compose ps`.
  2. Cowrie accepts `ssh root@host -p 2222` and logs the session.
  3. Dionaea responds on SMB:445 and HTTP:80 with banner-grabs.
  4. Zeek produces `conn.log` / `http.log` JSON entries within 60s of traffic.

## Notes / Next Steps

- Logs are written but not yet parsed, enriched, or stored centrally — that is Sprint 2's job (Filebeat → Logstash → Elasticsearch).
- The four data sources are intentionally heterogeneous; correlation across them is deferred to Sprint 3's forensic engine.
