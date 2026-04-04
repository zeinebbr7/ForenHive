# ForenHive — Sprint 2 Audit
**ETL Pipeline: Filebeat → Logstash → Elasticsearch**
*Branch: zeineb | Date: 2026-03-28*

---

## 1. Architecture Overview

Sprint 2 implements the data collection and normalization layer between the honeypot layer (Sprint 1) and the forensic engine (Sprint 3).

```
Cowrie   ──┐
Dionaea  ──┤──► Filebeat ──► Logstash ──► Elasticsearch
Galah    ──┤                  (ECS)       (daily indices)
Zeek     ──┘
```

**Stack versions:** Filebeat 8.13.0 · Logstash 8.13.0 · Elasticsearch 8.13.0

---

## 2. Components Implemented

### 2.1 Filebeat

**Role:** Tail log files from all 4 honeypots and forward events to Logstash over the Beats protocol (port 5044).

**Config file:** `pipeline/filebeat/filebeat.yml`

| Input | Path | Format | Tag |
|---|---|---|---|
| Cowrie | `/var/log/cowrie/log/cowrie/cowrie.json` | JSON | `cowrie` |
| Dionaea | `/var/log/dionaea/dionaea/dionaea.log` | Plain text | `dionaea` |
| Galah | `/var/log/galah/event_log.json` | JSON | `galah` |
| Zeek | `/var/log/zeek/current/conn.log` + `ssh.log` + `http.log` | JSON | `zeek` |

**Key settings:**
- `json.keys_under_root: true` — flattens JSON fields to event root (Cowrie, Galah, Zeek)
- `output.logstash.hosts: ["logstash:5044"]` — internal Docker network transport
- Running as `root` with `--strict.perms=false` (required after config file ownership change)
- 4 harvesters open simultaneously (one per honeypot source)

---

### 2.2 Logstash

**Role:** Receive events from Filebeat, apply per-honeypot transformations, normalize to ECS (Elastic Common Schema), enrich with GeoIP, and index to Elasticsearch.

**Config files:**
- `pipeline/logstash/logstash.yml` — runtime settings (4 workers, 125 batch size)
- `pipeline/logstash/pipelines/main.conf` — single unified pipeline

**Pipeline logic (per tag):**

#### Cowrie filter
- Adds `honeypot.type: cowrie`
- GeoIP enrichment on `src_ip` → `source.geo`
- Field renames to ECS: `src_ip` → `source.ip`, `dst_ip` → `destination.ip`, `username` → `user.name`, `eventid` → `event.id`, `session` → `session.id`, etc.
- Grok extraction of command from `message` when `event.id` starts with `cowrie.command`
- Event categorization: `authentication` / `process` / `session` / `network`
- Outcome tagging: `success` / `failure` for login events
- Forensic field preservation: `shasum` → `file.hash.sha256`, `duration` → `event.duration`, `size` → `network.bytes`, `ttylog` → `cowrie.ttylog`
- Timestamp correction: `date` filter parses Cowrie's `timestamp` (ISO8601) → `@timestamp` (Africa/Tunis)

#### Dionaea filter
- Adds `honeypot.type: dionaea`, `event.category: network`
- Grok parsing of plain-text log format (4 patterns for connection events)
- Drops lines that don't match any pattern (`_dionaea_grok_failed` tag)
- **Drops debug-level messages** (`dionaea.level == "debug"`) — eliminates internal thread noise
- GeoIP enrichment on `source.ip` when present

#### Galah filter
- Adds `honeypot.type: galah`, `event.category: web`
- GeoIP enrichment on `srcIP` → `source.geo`
- Full nested field rename to ECS: `[httpRequest][method]` → `http.request.method`, `[httpRequest][request]` → `http.request.uri`, `[httpRequest][userAgent]` → `user_agent.original`, etc.
- LLM metadata preserved: `galah.response.source` (llm/cache/static), `galah.llm.model`
- Timestamp correction: strips Go monotonic clock suffix, truncates to ms, parses `eventTime` → `@timestamp` (UTC — Galah container clock runs UTC)
- Cleanup: removes raw nested objects (`httpRequest`, `httpResponse`, `responseMetadata`)

#### Zeek filter
- Adds `honeypot.type: zeek`, `event.category: network`
- GeoIP enrichment on `id.orig_h`
- Field renames: `id.orig_h` → `source.ip`, `id.resp_h` → `destination.ip`, `proto` → `network.transport`
- Timestamp: `date` filter converts Zeek UNIX `ts` → `@timestamp`

#### Common cleanup (all events)
- Removes Filebeat metadata noise: `agent`, `ecs`, `input`, `host`

---

### 2.3 Elasticsearch

**Role:** Store normalized events in time-series daily indices, queryable for forensic analysis and dashboards.

**Index pattern:** `honeypot-logs-YYYY.MM.dd`

**Config:**
- Single-node, no security (dev mode: `xpack.security.enabled=false`)
- JVM heap: 1 GB (`ES_JAVA_OPTS=-Xms1g -Xmx1g`)
- Persistent data volume: `elasticsearch-data`
- Internal only: port 9200 not exposed to host

---

## 3. Live Metrics (2026-03-28)

### 3.1 Elasticsearch Index Summary

| Index | Documents | Size |
|---|---|---|
| honeypot-logs-2026.03.25 | 2,181,537 | 426 MB |
| honeypot-logs-2026.03.26 | 2,178,251 | 599 MB |
| honeypot-logs-2026.03.27 | 2,327,903 | 638 MB |
| honeypot-logs-2026.03.28 | 4,745,360 | 1.2 GB |
| **TOTAL** | **11,432,051** | **~2.8 GB** |

### 3.2 Events by Honeypot (all time)

| Honeypot | Total Events | Rate |
|---|---|---|
| Dionaea | 11,431,147 | ~2.3M/day |
| Cowrie | 1,458 | ~365/day |
| Zeek | 277 | Active from 2026-03-28 only |
| Galah | 169 | ~42/day |

### 3.3 Per-Day Breakdown

| Date | Dionaea | Cowrie | Galah | Zeek |
|---|---|---|---|---|
| 2026-03-25 | 2,181,330 | 196 | 11 | 0 |
| 2026-03-26 | 2,178,110 | 117 | 24 | 0 |
| 2026-03-27 | 2,327,868 | 35 | 0 | 0 |
| 2026-03-28 | 4,743,839 | 1,110 | 134 | 277 |

### 3.4 Logstash Pipeline (since last restart)

| Metric | Value |
|---|---|
| Events in | 1,170 |
| Events out | 269 |
| Events dropped | 901 (Dionaea debug/noise) |

---

## 4. Bugs Found and Fixed

### Bug 1 — Zeek logs not reaching Elasticsearch (CRITICAL)
**Symptom:** 0 Zeek events in ES for 3 days (2026-03-25 to 2026-03-27).

**Root cause:** `logs/current` inside the Zeek container is a symlink to the absolute path `/usr/local/zeek/spool/zeek`. When the Filebeat container mounted `zeek-logs` at `/var/log/zeek`, following the symlink pointed to a path that did not exist in the Filebeat container's filesystem, resulting in an empty directory.

**Fix:**
- Added `zeek-spool` Docker volume mounted at the **same absolute path** (`/usr/local/zeek/spool`) in both Zeek and Filebeat containers, making the symlink resolvable from both.
- Reverted Filebeat paths from glob `*/conn.log` back to `current/conn.log` (the live symlink).

**Files changed:** `docker-compose.yml`, `pipeline/filebeat/filebeat.yml`

**Verified:** 277 Zeek events in ES on 2026-03-28.

---

### Bug 2 — Cowrie forensic fields silently dropped (MEDIUM)
**Symptom:** Fields `shasum`, `duration`, `size`, `ttylog` were listed in `remove_field` and permanently deleted from every Cowrie event.

**Root cause:** The Logstash filter was treating these as noise, but they carry critical forensic data — SHA-256 of downloaded malware, session duration, transfer size, terminal log reference.

**Fix:** Changed `remove_field` to `rename` for these fields, mapping to ECS-compliant names:
- `shasum` → `file.hash.sha256`
- `duration` → `event.duration`
- `size` → `network.bytes`
- `ttylog` → `cowrie.ttylog`

**File changed:** `pipeline/logstash/pipelines/main.conf`

---

### Bug 3 — @timestamp shows Filebeat ingest time, not event time (MEDIUM)
**Symptom:** `@timestamp` reflected when Filebeat processed the file (could be hours after the actual event), making timeline forensics unreliable.

**Root cause:** No `date` filter was applied to Cowrie or Galah — Logstash left `@timestamp` as set by Filebeat at ingest time. Zeek was already correct (had `date` filter on `ts`).

**Fix:** Added `date` filters:
- **Cowrie:** `timezone: Africa/Tunis` — parses `timestamp` field (ISO8601 with UTC Z suffix) → `@timestamp`, then removes `timestamp`
- **Galah:** `timezone: UTC` — strips Go monotonic clock suffix (`m=+...`), truncates nanoseconds to milliseconds, parses `eventTime` → `@timestamp`, then removes `eventTime` (Galah container clock is UTC)

**Verified:** Triggered a live Cowrie connection at 21:26:32 GMT+1 → `@timestamp: 2026-03-28T20:26:32Z` (correct UTC equivalent).

**File changed:** `pipeline/logstash/pipelines/main.conf`

---

### Bug 4 — Dionaea debug messages stored in Elasticsearch (MEDIUM)
**Symptom:** 99.9% of Dionaea events had no `source.ip` — they were internal thread debug messages (e.g., `Thread fn 0x... took 0.000279 ms`), stored and consuming ~1.3 GB/day of disk space.

**Root cause:** Grok pattern 2 matched all `[date] module file-debug: message` format lines, including internal debug messages that have no forensic value.

**Fix:** Added `if [dionaea.level] == "debug" { drop {} }` after the Grok match block.

**Verified:** New Dionaea events after restart show `debug msgs stored: 0`.

**File changed:** `pipeline/logstash/pipelines/main.conf`

---

### Bug 5 — Dionaea log file stopped writing (OPERATIONAL)
**Symptom:** `dionaea.log` (424 MB) stopped being updated at 19:35, `dionaea-errors.log` at 20:12. Filebeat stopped receiving new Dionaea events.

**Root cause:** Dionaea's logging subsystem stopped writing to its log files after extended runtime (likely related to the log file growing to 424 MB). The process continued running but output switched to stdout only.

**Fix:** Restarted the Dionaea container (`docker compose restart dionaea`). Both log files resumed updating immediately.

---

## 5. Field Mapping Summary

### Cowrie → Elasticsearch

| Source Field | ES Field | ECS? |
|---|---|---|
| `src_ip` | `source.ip` | ✅ |
| `dst_ip` | `destination.ip` | ✅ |
| `dst_port` | `destination.port` | ✅ |
| `username` | `user.name` | ✅ |
| `password` | `user.password` | ✅ |
| `eventid` | `event.id` | ✅ |
| `protocol` | `network.transport` | ✅ |
| `session` | `session.id` | ✅ |
| `shasum` | `file.hash.sha256` | ✅ |
| `duration` | `event.duration` | ✅ |
| `size` | `network.bytes` | ✅ |
| `ttylog` | `cowrie.ttylog` | custom |
| `timestamp` | `@timestamp` | ✅ |

### Galah → Elasticsearch

| Source Field | ES Field | ECS? |
|---|---|---|
| `srcIP` | `source.ip` | ✅ |
| `srcPort` | `source.port` | ✅ |
| `httpRequest.method` | `http.request.method` | ✅ |
| `httpRequest.request` | `http.request.uri` | ✅ |
| `httpRequest.userAgent` | `user_agent.original` | ✅ |
| `httpRequest.bodySha256` | `http.request.body.hash` | ✅ |
| `httpRequest.sessionID` | `session.id` | ✅ |
| `httpResponse.headers.Server` | `http.response.server` | custom |
| `responseMetadata.generationSource` | `galah.response.source` | custom |
| `responseMetadata.info.model` | `galah.llm.model` | custom |
| `sensorName` | `observer.name` | ✅ |
| `port` | `destination.port` | ✅ |
| `eventTime` | `@timestamp` | ✅ |

### Zeek → Elasticsearch

| Source Field | ES Field | ECS? |
|---|---|---|
| `id.orig_h` | `source.ip` | ✅ |
| `id.orig_p` | `source.port` | ✅ |
| `id.resp_h` | `destination.ip` | ✅ |
| `id.resp_p` | `destination.port` | ✅ |
| `proto` | `network.transport` | ✅ |
| `ts` (UNIX) | `@timestamp` | ✅ |

---

## 6. Known Limitations

| Item | Description | Impact |
|---|---|---|
| GeoIP fails on internal IPs | Docker 172.x addresses have no GeoIP record | `_geoip_lookup_failure` tag on internal connections; public attacker IPs resolve correctly |
| Dionaea non-debug noise | `info` and `warning` level Dionaea messages without `source.ip` (startup messages) still stored | Minor disk overhead, not attack data |
| Dionaea log rotation | No log rotation configured; `dionaea.log` will grow until container restart is required | Manual restart needed periodically |
| Dionaea `@timestamp` = ingest time | No `date` filter for Dionaea — `@timestamp` was Filebeat processing time, not actual event time | ✅ Fixed in Sprint 3 (2026-04-04) — see Bug 6 |
| Elasticsearch no auth | `xpack.security.enabled=false` — dev configuration | Not suitable for production without TLS + credentials |

---

---

### Bug 6 — Dionaea `@timestamp` set to Filebeat ingest time (MEDIUM) *(fixed 2026-04-04)*

**Symptom:** All Dionaea events had `@timestamp` reflecting when Filebeat ingested the log line, not the actual time of the network connection. This made Dionaea events unusable in timeline forensics.

**Root cause:** The Logstash pipeline had `date` filters for Cowrie, Galah, and Zeek — but Dionaea was missed. Grok pattern 2 correctly extracted a `dionaea.date` field (`yyyy-MM-dd HH:mm:ss`) but nothing converted it to `@timestamp`.

**Fix:** Added a conditional `date` filter inside the Dionaea block (after `drop` statements):
```logstash
if [dionaea.date] {
  date {
    match    => ["dionaea.date", "yyyy-MM-dd HH:mm:ss"]
    target   => "@timestamp"
    timezone => "Africa/Tunis"
    remove_field => ["dionaea.date"]
  }
}
```
Guard with `if [dionaea.date]` because only grok pattern 2 produces this field — connection events (patterns 1, 3, 4) have no embedded timestamp.

**File changed:** `pipeline/logstash/pipelines/main.conf`

---

## 7. Sprint 2 Status: COMPLETE ✅

All 4 honeypot pipelines are operational. Events are normalized to ECS, timestamped in Africa/Tunis (GMT+1), and indexed in daily Elasticsearch indices. The pipeline is ready to serve the forensic engine (Sprint 3).
