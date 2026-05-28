# Sprint 2 — ETL Pipeline (Filebeat → Logstash → Elasticsearch)

## Sprint Overview

- **Sprint name:** ETL Pipeline
- **Sprint number:** 2
- **Goal:** Turn the heterogeneous JSON streams emitted by the four Sprint 1 honeypots into a single normalised, geo-enriched, queryable event store.

## Objectives

- Ship a classic Elastic-stack pipeline from honeypot logs to a searchable index.
- Normalise every event to the Elastic Common Schema (ECS) so downstream code can query consistent field names regardless of source.
- Enrich each source IP with GeoIP (city + country) and ASN data at ingest time.
- Keep the pipeline the **only** bridge between the isolated `honeypot-net` and `backend-net`.

## Tasks Completed

- **Filebeat** tails every honeypot log file from the shared volume and forwards to Logstash over the Beats protocol; tags each line with its honeypot of origin.
- **Logstash** parses each source, normalises fields to ECS, applies grok/dissect where needed, and enriches `source.ip` with MaxMind GeoLite2 City + ASN.
- **Elasticsearch** stores events in **daily indices** `honeypot-logs-YYYY.MM.dd`. In pre-prod the cluster indexed **11.4 M+ events**.
- **Per-honeypot parsing branches** for Cowrie eventids, Dionaea connection records, Galah HTTP, and Zeek conn/http/dns logs.
- **Static IP labelling** via an ip-map config so known scanners or internal IPs can be flagged or excluded downstream.

## Technical Details

```
Cowrie/Dionaea/Galah/Zeek JSON  →  Filebeat  →  Logstash:5044  →  Elasticsearch:9200
                                  (ship)        (parse/enrich)    (index)
```

- All three services are stock Elastic 8.13 Docker images, configured exclusively through bind-mounted YAML/conf files (no custom builds).
- GeoLite2 databases are bind-mounted read-only from `geoip/` (see [docker-compose.yml](../../docker-compose.yml)) to keep the heavy `.mmdb` files out of the container image.
- Indices roll daily; downstream code in Sprint 3 reads via the wildcard `honeypot-logs-*`.
- Logstash and Elasticsearch live on `backend-net`; Filebeat is the single container straddling `honeypot-net` and `backend-net`.

### File map

**`pipeline/filebeat/`**
- [`filebeat.yml`](../../pipeline/filebeat/filebeat.yml) — one prospector per honeypot log path, JSON decoding enabled, output pointed at `logstash:5044`. Sets `fields.honeypot: cowrie | dionaea | galah | zeek` so Logstash can branch parsing.

**`pipeline/logstash/`**
- [`logstash.yml`](../../pipeline/logstash/logstash.yml) — pipeline workers, queue type, HTTP API port, X-Pack monitoring off.
- [`pipelines/main.conf`](../../pipeline/logstash/pipelines/main.conf) — the ETL logic:
    1. **input** — Beats listener on 5044.
    2. **filter** — per-honeypot parsing, ECS field remapping, GeoIP + ASN enrichment, noise drops.
    3. **output** — Elasticsearch with daily index pattern.
- [`config/ip_map.yml`](../../pipeline/logstash/config/ip_map.yml) — static IP-to-label map used by the filter stage.

## Challenges & Solutions

- **Heterogeneous schemas** — every honeypot emits its own field names. Solved by enforcing ECS mapping at ingest in Logstash, so the backend never sees per-source schemas.
- **GeoIP database size** — bundling `.mmdb` files into the image would bloat it and freeze the dataset. Solved by bind-mounting from `geoip/` read-only, decoupling DB refresh from image rebuilds.
- **Network isolation vs. ingest** — honeypots must stay off `backend-net`, but logs must reach Elasticsearch. Solved by keeping Filebeat as the only dual-homed container.

## Outcomes / Deliverables

- A live `honeypot-logs-YYYY.MM.dd` daily index pattern in Elasticsearch, growing in real time.
- ECS-shaped documents with `source.geo.country_iso_code` and `as.*` populated at ingest.
- Validation gates passed:
  1. `curl http://elasticsearch:9200/_cat/indices?v` shows the daily index growing.
  2. Documents contain ECS-shaped `source.geo.country_iso_code` (GeoIP fired).
  3. All four honeypots are represented (`terms` aggregation on `fields.honeypot`).
  4. Logstash pipeline lag stays under one second in node-stats.

### Downstream contract for Sprint 3

- Index pattern `honeypot-logs-*` is the source of truth.
- Every document has `@timestamp`, `source.ip`, `event.action`, `honeypot`.
- IPs are pre-enriched with `geo.*` and `as.*`, so the forensic engine only adds reputation / threat-intel on top.

## Notes / Next Steps

- The pipeline indexes events but does not correlate or score them — that becomes Sprint 3's forensic engine.
- Reputation, YARA, VirusTotal, MITRE mapping, and chain-of-custody are explicitly out of scope here and handled downstream.
