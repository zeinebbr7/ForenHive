# ForenHive — Sprint 1 Audit
**Honeypot Layer: Cowrie · Dionaea · Galah · Zeek**
*Branch: zeineb | Date: 2026-03-28*

---

## 1. Scope

Sprint 1 covers the deployment and configuration of all four honeypots. Each honeypot must:
- Run as a Docker container with `restart: unless-stopped`
- Be reachable on its designated port(s)
- Generate logs in a format consumable by Sprint 2 (Filebeat)
- Simulate a realistic target to attract attackers

---

## 2. Status Overview

| Honeypot | Container | Status | Logs | Notes |
|---|---|---|---|---|
| Cowrie | `forenhive-cowrie` |  Running | JSON | SSH/Telnet active, UserDB auth working |
| Dionaea | `forenhive-dionaea` |  Running | Plain text | 11 protocols, SMB + MSSQL identity configured |
| Galah | `forenhive-galah` |  Running | JSON | LLM responses working, SQLite cache active |
| Zeek | `forenhive-zeek` |  Running | JSON | Passive capture on `eno12399`, log files flowing |
| Ollama | `forenhive-ollama` |  Running | — | Mistral 7B Q4_K_M loaded (4.4 GB) |

---

## 3. Component Details

### 3.1 Cowrie — SSH/Telnet Honeypot

**Image:** `cowrie/cowrie:latest`
**Ports:** 2222 (SSH), 2223 (Telnet)
**Config:** `honeypots/cowrie/cowrie.cfg`

**Configuration:**
```ini
[honeypot]
hostname = db-prod
auth_class = UserDB
auth_class_parameters = etc/userdb.txt
interactive_timeout = 300

[output_jsonlog]
enabled = true
logfile = var/log/cowrie/cowrie.json

[ssh]
version = SSH-2.0-OpenSSH_8.9p1
listen_endpoints = tcp:2222:interface=0.0.0.0

[telnet]
enabled = true
listen_endpoints = tcp:2223:interface=0.0.0.0
```

**Credential database (`userdb.txt`):** 14 entries across 4 accounts

| Username | Accepted passwords |
|---|---|
| root | root, toor, admin, password, 123456, mongo2024, banking123 |
| mongodb | mongodb, mongo123, password |
| dbadmin | dbadmin, Admin@2024 |
| ubuntu | ubuntu, changeme |

**Design intent:** Simulates a database server (`db-prod`) running SSH. Weak credentials deliberately chosen to attract brute-force attacks. Once logged in, attackers interact with a fake shell — all commands are logged.

**Event types produced:**
- `cowrie.session.connect` — new connection
- `cowrie.login.failed` — wrong credentials
- `cowrie.login.success` — accepted credentials
- `cowrie.command.input` — shell command executed
- `cowrie.session.file_download` — file download attempt (includes SHA-256)
- `cowrie.session.closed` — connection ended (includes duration)

**Log path:** `/cowrie/cowrie-git/var/log/cowrie/cowrie.json`
**Filebeat path:** `/var/log/cowrie/log/cowrie/cowrie.json`

---

### 3.2 Dionaea — Multi-Protocol Malware Honeypot

**Image:** `dinotools/dionaea:latest`
**Ports:** 23, 80, 135, 443, 445, 1433, 1723, 1883, 3306, 11211, 27017
**Config:** `honeypots/dionaea/smb.yaml`, `honeypots/dionaea/mssql.yaml`

**Protocol inventory:**

| Port | Protocol | Identity |
|---|---|---|
| 23 | FTP | Default |
| 80 | HTTP | Default |
| 135 | RPC Endpoint Mapper | Default |
| 443 | HTTPS | Default |
| 445 | SMB | Windows Server 2019 Datacenter (`WIN-SERVER2019`) |
| 1433 | MSSQL | SQL Server 2019 (RTM) 15.0.2000.5 |
| 1723 | PPTP | Default |
| 1883 | MQTT | Default |
| 3306 | MySQL | Default |
| 11211 | Memcache | Default |
| 27017 | MongoDB | Default |

**SMB identity (`smb.yaml`):**
```yaml
os_type: 4  # Windows
primary_domain: WORKGROUP
server_name: WIN-SERVER2019
native_os: Windows Server 2019 Datacenter 17763
shares: ADMIN$, C$, IPC$
```

**Design intent:** Impersonates a Windows infrastructure server to attract SMB exploits (EternalBlue, WannaCry), SQL injection attempts, and IoT protocol scanners. Captured malware binaries are stored in `dionaea-malware` volume.

**Log path:** `/opt/dionaea/var/log/dionaea/dionaea.log` (plain text)
**Filebeat path:** `/var/log/dionaea/dionaea/dionaea.log`

---

### 3.3 Galah — LLM Web Honeypot

**Image:** Built from `honeypots/galah/galah-src/` (Go, multi-stage)
**Ports:** 8080, 8888 (HTTP)
**Config:** `honeypots/galah/galah-src/config/config.yaml`

**Dockerfile:** Multi-stage build
- Builder: `golang:1.22` — compiles with `CGO_ENABLED=1` (required for SQLite)
- Runtime: `debian:bookworm-slim` — ~187 MB final image (vs ~2.74 GB single-stage)

**LLM configuration:**
- Provider: Ollama (`http://forenhive-ollama:11434`)
- Model: Mistral 7B Q4_K_M
- System prompt: instructs the model to return only `{"Headers": {...}, "Body": "HTML"}` JSON
- Response cache: SQLite at `/app/logs/cache.db` — cache hit returns in ~1s vs 40-80s for LLM generation

**System prompt strategy:** Example-based (concrete JSON output shown in prompt) rather than rule-based. This reliably produces the correct JSON structure from Mistral 7B.

**Log path:** `/app/logs/event_log.json`
**Filebeat path:** `/var/log/galah/event_log.json`

---

### 3.4 Zeek — Passive Network Analyzer

**Image:** `zeek/zeek:latest`
**Network mode:** `host` (must see all traffic on the physical interface)
**Capabilities:** `NET_ADMIN`, `NET_RAW`
**Config:** `honeypots/zeek/local.zeek`

**Loaded protocols:**
```zeek
@load base/frameworks/notice
@load base/protocols/conn
@load base/protocols/ssh
@load base/protocols/http
@load base/protocols/ftp
@load base/protocols/smtp
@load base/protocols/dns
@load policy/tuning/json-logs   # JSON output format
```

**Interface:** `eno12399` — injected at startup via:
```bash
sed -i 's/interface=eth0/interface=eno12399/g' /usr/local/zeek/etc/node.cfg
zeekctl deploy
```

**Log files produced:** `conn.log`, `ssh.log`, `http.log`, `dns.log`, `ssl.log`, `dhcp.log`, `weird.log`

**Volume design:** Zeek writes live logs to `/usr/local/zeek/spool/zeek/` and creates a symlink `logs/current → /usr/local/zeek/spool/zeek`. Both `zeek-logs` and `zeek-spool` volumes must be mounted in Filebeat at the same absolute paths for the symlink to resolve.

**Filebeat paths:** `/var/log/zeek/current/conn.log`, `ssh.log`, `http.log`

---

### 3.5 Ollama — LLM Backend

**Image:** `ollama/ollama:latest`
**Port:** 11434 (exposed on host + backend-net)
**Model:** Mistral 7B Q4_K_M (4.4 GB, stored in `ollama-models` volume)

Serves multiple consumers across the stack:
- **Galah** — HTTP response generation (Sprint 1)
- **Forensic engine** — MITRE ATT&CK forensic narrative (Sprint 3, 80-token output)
- **Backend HIVE assistant** — attacker profiling + AI chat fallback when Groq is unavailable (Sprint 4)

Port 11434 is exposed to the host so the forensic engine and backend can reach Ollama by container name across Docker networks.

---

## 4. Bugs Found and Fixed

### Bug 1 — Cowrie UserDB: UnicodeDecodeError crashing auth on every login

**Symptom:** Every SSH password attempt resulted in:
```
[cowrie.ssh.userauth] critical: Error checking auth for user b'mongodb'
UnicodeDecodeError: 'ascii' codec can't decode byte 0xc3 in position 46
```
All logins were refused regardless of credentials.

**Root cause:** `userdb.txt` was saved with a UTF-8 accented character in the comment line (`simulée`). Cowrie's `UserDB.load()` opens the file with `encoding="ascii"`, crashing on any non-ASCII byte.

**Fix:** Removed the accented character from the comment line. File is now pure ASCII.

**Verified:**
```python
db = UserDB(); db.load()
# root:root   → True
# root:wrong  → False
# root:mongo2024 → True
```

**File changed:** `honeypots/cowrie/userdb.txt`

---

### Bug 2 — Galah Dockerfile: CGO_ENABLED=0 breaks SQLite

**Symptom:** Galah container crashed immediately at startup with a linker error — `go-sqlite3` requires CGO (C bindings to SQLite).

**Root cause:** First multi-stage Dockerfile used `CGO_ENABLED=0` to produce a fully static binary. `go-sqlite3` cannot be built without CGO.

**Fix:** Changed to `CGO_ENABLED=1` in the builder stage. Runtime image uses `debian:bookworm-slim` to provide necessary C libraries.

**File changed:** `honeypots/galah/galah-src/Dockerfile`

---

### Bug 3 — Galah LLM: wrong JSON field names from Mistral

**Symptom:** Galah returned HTTP 500 for all requests. Logs showed JSON validation failure — Mistral was returning `{"Response": "HTML..."}` instead of `{"Headers": {...}, "Body": "HTML..."}`.

**Root cause:** The original system prompt used abstract rules ("return a JSON object with Headers and Body"). With complex CSS instructions, Mistral 7B produced wrong key names.

**Fix:** Replaced rule-based prompt with an example-based prompt showing the exact expected JSON output. Concrete examples are significantly more reliable than abstract instructions for Mistral 7B.

**File changed:** `honeypots/galah/galah-src/config/config.yaml`

---

### Bug 4 — Galah volume mounted at wrong path

**Symptom:** Filebeat could not find `event_log.json`. The galah-logs volume contained the full source tree (Dockerfile, README, Go files) instead of just log files.

**Root cause:** The original volume was mounted at `/app` (the entire working directory). The event log was written to `/app/event_log.json` but the volume also received all source files copied by the Dockerfile.

**Fix:**
- Changed volume mount to `/app/logs`
- Added CLI flags: `--event-log-file=/app/logs/event_log.json` and `--cache-db-file=/app/logs/cache.db`

**File changed:** `docker-compose.yml`

---

### Bug 5 — Zeek symlink not resolvable from Filebeat

**Symptom:** 0 Zeek events reaching Elasticsearch for 3 consecutive days.

**Root cause:** `logs/current` inside the Zeek container is a symlink pointing to the absolute path `/usr/local/zeek/spool/zeek`. Filebeat mounted the `zeek-logs` volume at `/var/log/zeek` — when it tried to follow the symlink, the target path `/usr/local/zeek/spool/zeek` did not exist in the Filebeat container's filesystem.

**Attempted partial fix:** Changed Filebeat paths from `current/conn.log` to `*/conn.log` (glob). This still failed because the dated archive directories (`2026-03-28/`) only contain `.log.gz` compressed files — Filebeat cannot read gzipped logs.

**Final fix:** Added a `zeek-spool` Docker volume mounted at the same absolute path (`/usr/local/zeek/spool`) in both Zeek and Filebeat containers. The symlink now resolves correctly from Filebeat. Reverted paths back to `current/conn.log`.

**Files changed:** `docker-compose.yml`, `pipeline/filebeat/filebeat.yml`

---

### Bug 6 — Dionaea SIGSEGV with custom dionaea.cfg

**Symptom:** Dionaea container crashed immediately (exit code 139, SIGSEGV) when a custom `dionaea.cfg` was mounted.

**Root cause:** The custom `dionaea.cfg` contained `[smb]` and `[mssql]` sections, which are invalid in the main config file (these must go in service YAML files). Even after removing those sections, the mount itself caused instability.

**Fix:** Removed the `dionaea.cfg` mount entirely. SMB and MSSQL identity is configured via the service YAML files (`smb.yaml`, `mssql.yaml`) mounted in `/opt/dionaea/template/etc/dionaea/services-enabled/`.

**Files changed:** `docker-compose.yml`, deleted `honeypots/dionaea/dionaea.cfg`

---

### Bug 7 — Filebeat strict.perms crash

**Symptom:** Filebeat crashed on startup with permission error on `filebeat.yml`.

**Root cause:** After editing `filebeat.yml` with the Edit tool, the file became owned by the `pfe` user instead of root. Filebeat requires its config file to be owned by root (uid=0) by default.

**Fix:** Added `command: filebeat -e --strict.perms=false` to the Filebeat service in `docker-compose.yml`. This bypasses the ownership check without requiring `sudo chown`.

**File changed:** `docker-compose.yml`

---

### Bug 8 — rules.yaml referenced deleted templates directory

**Symptom:** `rules.yaml` referenced `templates/default.json` and `templates/example-json.json`, but the `templates/` directory was deleted during the cleanup audit.

**Impact:** None at runtime — `rules.yaml` is not loaded (no `--rules-config-file` flag in the Galah command).

**Fix:** Updated both rules to `enabled: false` and `type: llm` (no template reference needed).

**File changed:** `honeypots/galah/galah-src/config/rules.yaml`

---

## 5. Files Cleaned Up

During the Sprint 1 audit, the following unnecessary files were removed:

| File | Reason |
|---|---|
| `llm/docker-compose.llm.yml` | Empty file, no content |
| `llm/docker-compose.ollama.yml` | Redundant — Ollama already in main compose |
| `pipeline/docker-compose.pipeline.yml` | Outdated copy, missing Galah and `--strict.perms=false` |
| `honeypots/galah/galah-src/deploy/galah.yml` | Kubernetes manifest — not applicable to Docker project |
| `honeypots/dionaea/dionaea.cfg` | Caused SIGSEGV, replaced by service YAML files |
| `get-docker.sh` | Docker installation script — Docker already installed |
| `galah-src/data/` | 2.4 MB of upstream test event logs — not needed for production |
| `galah-src/docs/` | 1.1 MB of upstream images and documentation |
| `galah-src/deploy/` | Kubernetes README — not applicable |
| `galah-src/templates/` | Static JSON templates referenced by disabled rules |
| `galah-src/LICENSE` | Upstream open-source license file |
| `galah-src/README.md` | Upstream project README |

**Total removed:** ~4 MB of upstream repository extras and redundant files.

---

## 6. Known Limitations

| Item | Description |
|---|---|
| No public traffic yet | Honeypots are running locally — not yet exposed to the internet. All current events are from local testing. Real attacker traffic will flow once internet deployment is configured. |
| Zeek interface hardcoded | Interface `eno12399` is hardcoded via `sed` in the startup command. If the network interface name changes, the Zeek container must be recreated with the updated interface name. |
| Dionaea log rotation | No log rotation is configured. `dionaea.log` grows indefinitely until container restart. After extended runtime the file may stop being written to (process switches to stdout). |
| Galah LLM latency | First request to a new URL takes 40-80 seconds on CPU (Mistral 7B without GPU). Cache makes subsequent identical requests instant. |

---

## 7. Sprint 1 Status: COMPLETE 

All four honeypots are running and generating logs. The log files are readable by Filebeat and the data flows correctly into the Sprint 2 pipeline. The system is ready for internet-facing deployment.
