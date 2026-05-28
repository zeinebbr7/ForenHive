# Sprint 3 — Forensic Engine

## Sprint Overview

- **Sprint name:** Forensic Engine
- **Sprint number:** 3
- **Goal:** Turn raw honeypot events into forensic evidence — enriched IPs, scored sessions, MITRE-mapped tactics, behavioural profiles, and a tamper-evident chain of custody.

## Objectives

- Build a standalone Python service that periodically reads from Elasticsearch and writes structured forensic artefacts to PostgreSQL.
- Chain enrichment, malware analysis, correlation, scoring, profiling, and custody-sealing into one orchestrated run.
- Produce an admissible chain of custody (ISO/IEC 27037) using SHA-256 + RFC 3161 timestamping.
- Keep all module outputs queryable by the future backend (Sprint 4) without schema changes.

## Tasks Completed

A single service `forenhive-forensic-engine` runs every 5 minutes (`ENGINE_INTERVAL_MINUTES=5`) and chains 11 analytical modules:

```
ES events → enrich IPs → scan files (YARA) → check VT → correlate SMB
        → build timeline → extract IoCs → map MITRE → score risk
        → profile suspect (LLM) → seal chain of custody (SHA-256 + RFC 3161)
```

- **IP enrichment** from MaxMind, AbuseIPDB, Shodan InternetDB, IPLocate, RDAP/Whois, reverse DNS.
- **Tiered YARA scanning** (CRITICAL/HIGH/MEDIUM) over Dionaea payloads, with 10 hand-picked rule families.
- **VirusTotal v3 lookup** by SHA-256, quota-aware.
- **SMB correlation** joining Dionaea SQLite with Zeek NTLM logs (EternalBlue, EPMapper, share enumeration).
- **Millisecond timeline** merging all honeypot events per session.
- **STIX 2.1-compatible IoC extraction** (9 types: URLs, hashes, CVEs, domains, …).
- **Hybrid MITRE ATT&CK mapping** — 15 deterministic rules for the IDs, LLM narrative only.
- **Risk score v2.0.0** — 9 orthogonal signals (WHO 33 + WHAT 43 + HOW 24), replacing an earlier 18-signal model with too-high inter-signal correlations.
- **Suspect Profiler** — FBI-BAU-style 4-section prompt (~2,600 tokens) with an Elasticsearch "ViCAP" memory of past profiles.
- **Chain of custody** — canonical JSON → SHA-256 → linked `prev_hash` chain → batch Merkle root → RFC 3161 TSA submission (freetsa.org + fallbacks).
- **`/health` endpoint** on port 8001 for `docker compose` and the SOC backend.

Detailed reference: [docs/forensic-engine.md](../forensic-engine.md).

## Technical Details

- Single Docker service built from [`forensic-engine/Dockerfile`](../../forensic-engine/Dockerfile).
- All modules share a `db_pool` (PostgreSQL) and a `quota_tracker` (for external APIs).
- The orchestrator (`engine.py`) is the only entry point: loads recent sessions, fans them through the 11 stages, commits results atomically, and exits. The container re-invokes it every 5 min.

### Pipeline modules (run in order)

1. [`enricher.py`](../../forensic-engine/enricher.py) — multi-source IP enrichment; caches into `ip_enrichment_cache`.
2. [`yara_scanner.py`](../../forensic-engine/yara_scanner.py) — tiered YARA over Dionaea binaries; writes `file_analysis`.
3. [`virustotal.py`](../../forensic-engine/virustotal.py) — SHA-256 lookup, merges detections into `file_analysis`.
4. [`smb_analyzer.py`](../../forensic-engine/smb_analyzer.py) — Dionaea ⨝ Zeek NTLM; writes ES index `forenhive-smb-analysis`.
5. [`timeline_builder.py`](../../forensic-engine/timeline_builder.py) — merges per-session events into `forensic_timeline_events`.
6. [`ioc_extractor.py`](../../forensic-engine/ioc_extractor.py) — pulls 9 IoC types into `forensic_iocs`.
7. [`mitre_mapper.py`](../../forensic-engine/mitre_mapper.py) — 15 if/else rules (`T1110.001`, `T1105`, `T1210`, …) for confidence=1.0 IDs + a ≤80-token Mistral narrative.
8. [`risk_score.py`](../../forensic-engine/risk_score.py) — 9-signal WHO/WHAT/HOW score (0-100) with per-signal breakdown.
9. [`profiler.py`](../../forensic-engine/profiler.py) — BAU 4-section prompt → Ollama → JSON → `suspect_profiles` + ES memory.
10. [`chain_of_custody.py`](../../forensic-engine/chain_of_custody.py) — SHA-256 linked chain, batch Merkle root, RFC 3161 TSA; writes `forensic_chain_of_custody` and `forensic_coc_batches`.
11. [`engine.py`](../../forensic-engine/engine.py) — orchestrator + CLI (`--hours`, `--enrich-only`, `--session …`).

### Support modules

- [`config.py`](../../forensic-engine/config.py) — env vars and filesystem paths, validated at import.
- [`db_pool.py`](../../forensic-engine/db_pool.py) — shared async PostgreSQL pool.
- [`risk_thresholds.py`](../../forensic-engine/risk_thresholds.py) — LOW/MEDIUM/HIGH/CRITICAL cutoffs.
- [`quota_tracker.py`](../../forensic-engine/quota_tracker.py) — per-API daily counters (VirusTotal, AbuseIPDB), persisted in `api_quota_status`.
- [`verify_coc.py`](../../forensic-engine/verify_coc.py) — CLI auditor: re-walks the chain, exits non-zero on first inconsistency.
- [`server.py`](../../forensic-engine/server.py) — minimal HTTP server on `:8001` exposing `/health`.

### Database

- [`db/schema.sql`](../../forensic-engine/db/schema.sql) — `ip_enrichment_cache`, `file_analysis`, `forensic_sessions`, `api_quota_status`, `forensic_timeline_events`, `forensic_iocs`, `forensic_chain_of_custody`, `forensic_coc_batches`, `suspect_profiles`, `ip_risk_scores`.
- [`db/init_db.py`](../../forensic-engine/db/init_db.py) — idempotent bootstrap.

### YARA rules ([`yara_rules/`](../../forensic-engine/yara_rules/))

10 hand-picked families: `credential_stealer.yar`, `crypto_miner.yar`, `emotet.yar`, `generic_shell.yar`, `linux_backdoor.yar`, `malware.yar`, `mirai.yar`, `ransomware.yar`, `rat.yar`, `wannacry.yar`. Tiered by severity so the scanner can stop early on a CRITICAL match.

### Tests

- [`tests/test_risk_score.py`](../../forensic-engine/tests/test_risk_score.py) — each of the 9 signals plus the RFC1918 special rule and the cap at 100.
- [`tests/conftest.py`](../../forensic-engine/tests/conftest.py) — shared fixtures (sample sessions, mocked enrichment).

## Challenges & Solutions

- **MITRE ID hallucinations from LLMs** — solved by splitting the mapper into deterministic if/else rules for the IDs and a token-capped LLM call (≤80 tokens) for narrative only. No ID ever comes from the model.
- **Over-correlated risk signals** — the earlier 18-signal model double-counted related behaviours. Replaced by a 9-signal v2.0.0 (WHO/WHAT/HOW) with orthogonal contributions, capped at 100.
- **Tamper-evidence for legal admissibility** — solved with a SHA-256 linked-hash chain plus RFC 3161 timestamping (freetsa.org + fallbacks), satisfying ISO/IEC 27037; `verify_coc.py` re-walks the chain on demand for auditors.
- **External API quotas** — `quota_tracker` enforces per-API daily counters reset at UTC midnight, persisted in `api_quota_status` so a restart does not lose the count.

## Outcomes / Deliverables

- A scheduled (5-minute) end-to-end run populating all forensic tables.
- Auditor CLI `verify_coc.py` that returns `chain intact`.
- Healthcheck endpoint on `:8001`.
- Validation gates passed:
  1. A scheduled run produces rows in `ip_enrichment_cache`, `forensic_sessions`, `forensic_timeline_events`, `forensic_iocs`, `suspect_profiles`, `forensic_chain_of_custody`, `ip_risk_scores`.
  2. `docker compose exec forensic-engine python verify_coc.py` returns `chain intact`.
  3. Risk-score unit tests green.
  4. `/health` on `:8001` returns 200.

## Notes / Next Steps

- The engine writes artefacts but exposes only `/health`. Surfacing sessions, IoCs, profiles, and CoC to operators is Sprint 4 (FastAPI backend).
- On-demand re-runs (per session) will be triggered by the backend via `forensic_runner` in Sprint 4.
