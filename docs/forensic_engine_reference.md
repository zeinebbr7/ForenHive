# ForenHive Forensic Engine — Full Reference

> The forensic engine is the **brain** of ForenHive. It reads raw honeypot
> traffic from Elasticsearch, enriches every attacker IP, scores every
> session against a 9-signal model, maps each one to MITRE ATT&CK,
> normalizes events into a tamper-evident timeline, extracts indicators of
> compromise, seals the result with a Merkle-rooted RFC-3161 timestamp,
> and asks an LLM to write a behavioral profile of each attacker. It
> produces the **legally-admissible forensic evidence** that the rest of
> the stack (backend API, frontend dashboard, reports) consumes.
>
> This document is the single source of truth for *how it works*. For the
> v1 → v2 scoring migration story see [sprint3_audit_v2.md](sprint3_audit_v2.md).
> For the v1 baseline see [sprint3_audit_final.md](sprint3_audit_final.md).

---

## Table of contents

1. [TL;DR](#1--tldr)
2. [Position in the system](#2--position-in-the-system)
3. [Execution modes](#3--execution-modes)
4. [End-to-end data flow](#4--end-to-end-data-flow)
5. [The 10-phase pipeline](#5--the-10-phase-pipeline)
6. [Phase 3 deep-dive — session scoring + MITRE](#6--phase-3-deep-dive--session-scoring--mitre)
7. [The 9-signal risk model](#7--the-9-signal-risk-model)
8. [Phase 9 deep-dive — unified per-IP scoring](#8--phase-9-deep-dive--unified-per-ip-scoring)
9. [Database schema (PostgreSQL)](#9--database-schema-postgresql)
10. [External dependencies & graceful degradation](#10--external-dependencies--graceful-degradation)
11. [Chain of custody — legal-grade integrity](#11--chain-of-custody--legal-grade-integrity)
12. [Configuration (environment variables)](#12--configuration-environment-variables)
13. [Operations: run, verify, troubleshoot](#13--operations-run-verify-troubleshoot)
14. [Module reference](#14--module-reference)
15. [Glossary](#15--glossary)

---

## 1 · TL;DR

**One sentence:** ES logs in → 10 phases (enrich → SMB → YARA+VT → score → timeline → IoCs → custody → LLM profile → alert → unified IP score) → PostgreSQL + Elasticsearch out, all idempotent, all tamper-evident, on a 5-minute scheduler.

**Three numbers:**
- **9 scoring signals** in 3 buckets (WHO 33 + WHAT 43 + HOW 24 = 100 points).
- **10 phases** orchestrated by [engine.py](../forensic-engine/engine.py).
- **2 storage sinks**: PostgreSQL (permanent audit trail) + Elasticsearch (search/aggregation).

**Two entry points to the scorer:**
- `score_session(session_data) -> ScoreResult` — per attacker session, Phase 3.
- `score_ip(ip, sessions, enrichment) -> ScoreResult` — per attacker IP across all their sessions, Phase 9.

**Two execution models:**
- **HTTP service** (`server.py` on port 8001) with an internal **scheduler** that re-runs the engine every `ENGINE_INTERVAL_MINUTES`.
- **CLI** (`python engine.py --hours 24` or `--<phase>-only`) — same code path, one-shot.

---

## 2 · Position in the system

```
 C1 Honeypots  ─►  C2 ETL Pipeline    ─►  C3 Forensic Engine  ─►  C4 Backend  ─►  C5 Frontend
 ─────────────     ────────────────       ────────────────         ─────────       ──────────
 Cowrie            Filebeat               ┌──────────────────┐    FastAPI         React
 Dionaea           Logstash               │   engine.py      │    + JWT           + dashboard
 Galah             Elasticsearch  ───────►│ 10 phases        │───►PostgreSQL      + attack map
 Zeek              (honeypot-logs-*)      │ + Ollama LLM     │    + ES indices
                                          └──────────────────┘
```

The engine is the **only** component that is both a **consumer** (reads ES) and a **producer** (writes PG + ES). It runs on the `backend-net` Docker network only (no exposure to `honeypot-net`). It depends on Elasticsearch, PostgreSQL, Ollama, and (optionally) AbuseIPDB / Shodan / VirusTotal / IPLocate / freetsa.org.

See [architecture.md](architecture.md) for the broader 5-layer view.

---

## 3 · Execution modes

The container's entrypoint is `python server.py` ([Dockerfile](../forensic-engine/Dockerfile)). `server.py` does **three** things:

### 3a · HTTP service (Flask, port 8001)
Exposes endpoints for ad-hoc runs and status. The backend calls these (e.g. `POST /run` triggers a one-shot run for the current 24 h window).

### 3b · Scheduler — `_engine_loop`
A daemon thread inside `server.py` that:
1. Sleeps 30 s after container start (let dependencies warm up).
2. Acquires `_engine_lock` (prevents overlapping cycles).
3. Spawns `engine.py` as a subprocess (fresh Python process → fresh imports, no in-memory staleness).
4. Sleeps `ENGINE_INTERVAL_MINUTES` (default 1440 = 24 h; live config 5 min).

The lock guards *only* the scheduler's own loop. A manual `docker exec python engine.py …` runs **outside** the lock — avoid running both at once to prevent interleaved writes.

### 3c · CLI flags ([engine.py](../forensic-engine/engine.py))

| Flag | Effect |
|---|---|
| (no flag) | Full pipeline — all 10 phases over `--hours` window |
| `--hours N` | Look back N hours (default 24) |
| `--enrich-only` | Phase 1 only |
| `--yara-only` | Phase 2a only |
| `--score-only` | Phase 3 only |
| `--timeline-only` | Phase 4 only |
| `--ioc-only` | Phase 5 only |
| `--coc-only` | Phase 6 only |
| `--smb-only` | Phase 0 only |
| `--profile-only` | Phases 3 + 7 |
| `--init-db` | Bootstrap schema and exit |
| `--quota-status` | Print external-API quota state and exit |
| `--quota-reset API` | Clear exhausted flag for an API |

---

## 4 · End-to-end data flow

```
  honeypot-logs-YYYY.MM.dd   ┌── PG  ip_enrichment_cache        (24 h TTL)
  ┌──────────────────┐       │
  │ Cowrie  Dionaea  │       ├── PG  file_analysis              (YARA + VT)
  │ Galah   Zeek     │       │
  └────────┬─────────┘       ├── PG  forensic_sessions          (score + MITRE)
           │ ES scroll       │
           ▼                 ├── PG  ip_risk_scores             (unified per-IP)
   ┌─────────────────┐       │
   │   engine.py     │──────►├── PG  forensic_timeline_events   (cross-HP events)
   │  10 phases      │       │
   └──────┬──────────┘       ├── PG  forensic_iocs              (deduped IoCs)
          │                  │
          │ Ollama prompt    ├── PG  forensic_chain_of_custody  + forensic_coc_batches
          ▼                  │
   ┌────────────────┐        ├── PG  suspect_profiles           (LLM behavioral)
   │ Ollama/Mistral │        │
   │ (profiler +    │        ├── ES  forenhive-suspect-profiles
   │  MITRE narr.)  │        ├── ES  forenhive-smb-analysis
   └────────────────┘        └── ES  forenhive-alerts
```

**Every writer is idempotent.** Sessions on `session_id`, timeline rows on `es_doc_id`, IoCs on `(type, value, source_ip)`, CoC on `session_id UNIQUE`, profiles on `source_ip UNIQUE`. Re-running the same window updates rather than duplicates.

---

## 5 · The 10-phase pipeline

`ForensicEngine.run_full_analysis(hours_back)` calls these in fixed order:

| # | Phase | Module | Writes to | CLI flag |
|---|---|---|---|---|
| 1 | IP Enrichment | [enricher.py](../forensic-engine/enricher.py) | `ip_enrichment_cache` | `--enrich-only` |
| 0 | SMB Forensics | [smb_analyzer.py](../forensic-engine/smb_analyzer.py) | ES `forenhive-smb-analysis` | `--smb-only` |
| 2a | YARA Scan | [yara_scanner.py](../forensic-engine/yara_scanner.py) | `file_analysis` | `--yara-only` |
| 2b | VirusTotal | [virustotal.py](../forensic-engine/virustotal.py) | `file_analysis` (enriched) | (auto) |
| 3 | Session Scoring + MITRE | [risk_score.py](../forensic-engine/risk_score.py) + [mitre_mapper.py](../forensic-engine/mitre_mapper.py) | `forensic_sessions` | `--score-only` |
| 4 | Timeline | [timeline_builder.py](../forensic-engine/timeline_builder.py) | `forensic_timeline_events` | `--timeline-only` |
| 5 | IoC Extraction | [ioc_extractor.py](../forensic-engine/ioc_extractor.py) | `forensic_iocs` | `--ioc-only` |
| 6 | Chain of Custody | [chain_of_custody.py](../forensic-engine/chain_of_custody.py) | `forensic_chain_of_custody`, `forensic_coc_batches` | `--coc-only` |
| 7 | LLM Profiler | [profiler.py](../forensic-engine/profiler.py) | `suspect_profiles` + ES `forenhive-suspect-profiles` | `--profile-only` |
| 8 | Alert Evaluation | (in `engine.py`) | ES `forenhive-alerts`, optional WhatsApp | — |
| 9 | Unified IP Scoring | `score_ip()` + `_store_unified_risk_score` | `ip_risk_scores` | — |

> Phase numbering reflects history: Phase 0 (SMB) was added later but **runs after Phase 1** because it depends on Phase 1's enrichment cache.

### Phase 1 — IP Enrichment
For every unique `source.ip` in the time window, run **five parallel lookups**:
- **MaxMind GeoLite2 City + ASN** (offline, ships with the image) — country, city, org, lat/lon, ASN.
- **AbuseIPDB v2** (`ABUSEIPDB_KEY`) — abuse_score, total_reports, distinct_users, attack categories, recent comments.
- **IPLocate** (free tier, no key) — `is_tor`, `is_vpn`, `is_proxy`, `is_datacenter`, `is_bogon`, ASN type.
- **Shodan InternetDB** (free, no key) — open ports, vulns (CVE list), tags, hostnames.
- **RDAP WHOIS** — network name, registry, registration data.

Results are cached in `ip_enrichment_cache` with a 24 h TTL. Private/internal IPs are flagged (`_classify_private_ip` → loopback / docker_bridge / corporate_internal) and skipped for external lookups (reputation + anonymization are also skipped at scoring time). Quotas are checked *before* each external call via `quota_tracker`.

### Phase 0 — SMB Forensics
Reads Dionaea's SQLite database (share-enum events, RPC opnums) and Zeek NTLM logs (challenge/response, domain, user). For each source IP, derives:
- `smb_share_enum` (T1135 indicator),
- `epmapper_prescan` count (T1046),
- `exploit_cve` list (MS08-067, EternalBlue, etc.),
- detected usernames + NTLM hashes,
- ATT&CK technique attribution.

Indexed to ES `forenhive-smb-analysis` (one doc per IP). Phase 3 reads this back via `_mget` to feed `lateral_movement`.

### Phase 2a — YARA Scan
Compiles every `.yar` file in [yara_rules/](../forensic-engine/yara_rules/) (fail-soft on bad rules). Walks Dionaea's captured-binaries directory, SHA-256s each file in 64 KB chunks, persists matches **with severity from rule metadata** (`meta: severity = critical|high|medium|low`) to `file_analysis`. Negative results are also written (enables negative caching — same hash won't be re-scanned).

Rule sets: Mirai, WannaCry, LockBit/BlackCat/Clop, AsyncRAT/QuasarRAT, XMRig, Emotet, generic shells, SSH brute-force binaries.

### Phase 2b — VirusTotal
Takes hashes from Phase 2a plus `file.hash.sha256` from Cowrie file downloads, calls `v3/files/{sha256}`. Free tier is **4 requests/day** — `virustotal.py` self-paces at 0.25 s/req, sets `_network_dead` on first network error, records HTTP 429 in `api_quota_status` with `reset_at` = next UTC midnight. Cache hits are reused; misses are stored.

### Phase 3 — Session Scoring + MITRE
The heart of the engine. See [§6](#6--phase-3-deep-dive--session-scoring--mitre).

### Phase 4 — Timeline build
Scrolls ES `honeypot-logs-*` in batches of 1 000 documents. Each event is routed through one of four normalizers (`_norm_cowrie`, `_norm_dionaea`, `_norm_galah`, `_norm_zeek`) that produce a uniform schema: `{ts_ms, source_ip, honeypot_type, event_type, action, target, payload}`. Upserts into `forensic_timeline_events` keyed on `es_doc_id UNIQUE`. Supports both nested (`a.b.c`) and flat-dotted (`a.b.c` as a single key) ES schemas.

### Phase 5 — IoC extraction
Regex-scans the timeline for **10 IoC types**:
`url, domain, ipv4_external, sha256, md5, cve, user_agent, cmdline, file_path, email, http_path`.

Each IoC is deduplicated on `(ioc_type, ioc_value, source_ip)` and tracked with `first_seen`, `last_seen`, `occurrences`, and the set of `honeypot_types` it appeared in (merge-on-upsert via PG arrays).

### Phase 6 — Chain of custody
Three-layer integrity. See [§11](#11--chain-of-custody--legal-grade-integrity).

### Phase 7 — LLM Profiler
For each distinct source IP with `risk_score >= PROFILE_RISK_MIN`, builds a 4-section prompt (~3 000 tokens):
1. **System role** — FBI Behavioral Analysis Unit persona, JSON-only output contract.
2. **Criminology framework** — decision rules for *organized vs. disorganized*, sophistication tiers, primary-objective taxonomy, disguise-detection logic, signature-vs-MO distinction.
3. **Evidence** — session metadata, enrichment, timeline category counts, SMB data, MITRE techniques, risk score (XML-delimited).
4. **Reference cases** — up to 5 similar past profiles retrieved from `forenhive-suspect-profiles` via an ES `bool/should` over MITRE techniques (weight 3), ASN (2), country (1), risk score ±15 (1).

Calls Ollama (`mistral:latest`, `T=0.3, num_ctx=8192, timeout=300 s`), parses JSON, and dual-sinks to PG `suspect_profiles` (`source_ip UNIQUE`) and ES `forenhive-suspect-profiles/_doc/profile-{ip}`. On Ollama failure, retries once; second failure stores a minimal `confidence=0.0` profile.

Output schema (enforced by prompt + validated on parse):
```
sophistication      : amateur | intermediate | expert | unknown
confidence          : 0.0–1.0
primary_objective   : credential_harvesting | botnet_recruitment | …
secondary_objective : … | null
behavioral_traits   : [string]
organized_score     : 0.0–1.0
disguise_used       : bool      disguise_type : tor | vpn | proxy | none
escalation_detected : bool      mitre_techniques : [Txxxx]
dominant_tactic     : string    kill_chain_phase : string
signature_indicators: [string]  similar_past_cases : 0–5
risk_score          : 0–100
detective_narrative : 3–5 sentences
```

### Phase 8 — Alert evaluation
Sessions scoring `>= ALERT_INDEX_MIN` are indexed to ES `forenhive-alerts`. Sessions scoring `>= ALERT_NOTIFY_MIN` *also* trigger a WhatsApp message via Twilio (if `TWILIO_*` env vars set). Quiet-hours suppression and per-IP rate limiting prevent floods.

### Phase 9 — Unified per-IP scoring
For every unique IP that had at least one session in the window, aggregate across all their sessions (Cowrie + Dionaea + Galah) into a single 0–100 score via `score_ip()`. Stored in `ip_risk_scores`. See [§8](#8--phase-9-deep-dive--unified-per-ip-scoring).

---

## 6 · Phase 3 deep-dive — session scoring + MITRE

This is where the pipeline turns "raw events" into "scored evidence." The order of operations matters.

```python
# Per session:

# (a) Behavioral fetch — BEFORE scoring, so quality signals can fire
if session["honeypot_type"] == "cowrie":
    session_data["commands"]            = _query_cowrie_commands(es, sid)
    session_data["file_download_count"] = _query_cowrie_file_downloads(es, sid)

# (b) MITRE — deterministic technique IDs feed the scorer's sophistication signal
tech_ids         = get_techniques_deterministic(session_data)
kill_chain_phase = get_kill_chain_phase(tech_ids)
kill_chain_stage = get_kill_chain_stage_number(kill_chain_phase)
session_data["mitre_techniques"] = tech_ids
session_data["kill_chain_stage"] = kill_chain_stage

# (c) 9-signal scoring
result = score_session(session_data)      # → ScoreResult dataclass

# (d) LLM narrative (techniques already known; no re-derivation)
mitre_full = self.mitre.narrative_for(session_data, tech_ids)

# (e) Persist to forensic_sessions (bulk upsert, one transaction)
session["risk_score"]    = result.risk_score
session["score_version"] = result.score_version
session["enrichment_data"] = {
    **enrich,
    "risk_level":         result.risk_level,
    "confidence":         result.confidence,
    "score_version":      result.score_version,
    "signal_breakdown":   result.signal_breakdown,
    "active_signals":     result.active_signals,
    # … plus enriched WHO/WHAT/HOW fields so Phase 9 can read them back
}
sessions_to_save.append(session)
```

**Three architectural rules** make this work cleanly:
1. **MITRE before scoring.** Techniques are derived deterministically (16-entry rule table → guaranteed `confidence=1.0`, no LLM hallucination) and *then* fed to the scorer's `mitre_sophistication` signal. The LLM only writes the narrative paragraph.
2. **Quality before count.** Cowrie commands are fetched up front so `compromise_depth` can detect `cat /etc/shadow`, `rm -rf /`, `ssh root@x` — credential-access / destructive / lateral-cmd patterns — rather than just counting commands.
3. **Phase 3 persists everything Phase 9 needs.** `smb_share_enum`, `epmapper_prescan`, `exploit_cve`, `previously_seen`, `previous_sessions`, `shodan_vulns`, `is_bogon`, `geo_country_code`, `destination_port` are all stored in `enrichment_data` so Phase 9 doesn't have to re-fetch from ES.

---

## 7 · The 9-signal risk model

Implemented in [risk_score.py](../forensic-engine/risk_score.py) (v2.0.0, `SCORE_VERSION = "2.0.0"`). Each signal is a pure function `(d: dict) -> SignalDetail`. Inputs are defensively coerced; one signal raising an exception becomes a 0-pt skipped detail, never crashes the score.

### Taxonomy — WHO / WHAT / HOW (FBI-BAU framing)

```
WHO  (33)  ── reputation 15 · anonymization 10 · threat_history 8
WHAT (43)  ── intent_volume 10 · compromise_depth 15 · exfiltration 8 · lateral_movement 10
HOW  (24)  ── malware 12 · mitre_sophistication 12
                                                              = 100
```

### Signal-by-signal

**1 · reputation (WHO, max 15)** — AbuseIPDB confidence. Skipped for private IPs.
Buckets: ≥90→15, ≥70→11, ≥50→7, ≥25→4, else 0. Evidence: abuse_score, total_reports, distinct_users, categories.

**2 · anonymization (WHO, max 10)** — how hidden the origin is. Skipped for private.
Priority: `is_bogon` → 10, `is_tor` → 10, `is_vpn ∨ is_proxy` → 6, `is_datacenter` → 3, else 0. Evidence: 5 booleans + ASN + org.

**3 · threat_history (WHO, max 8)** — additive, capped at 8.
- recidivism: `min(4, int(2·log2(1+previous_sessions)))`
- `is_abuser_listed` +1; `threat_tier == "high"` +1
- country: sanctioned {KP, IR, SY, CU, VE} +2; high-threat {RU, CN, BY} +1
- Shodan vulns: `min(2, len(vulns))`

**4 · intent_volume (WHAT, max 10)** — effort and recon intent.
- effective attempts = `attempts` (cowrie) or `attempts × 0.5` (others)
- `base = min(6, int(2·log10(1 + effective)))`
- velocity bonus: > 50/s → 2, > 10/s → 1
- scan-path bonus: `min(3, hits)` across `http_paths ∪ commands` vs `_SCAN_PATHS`

**5 · compromise_depth (WHAT, max 15)** — did they get in and what did they do.
- Returns 0 if `success_count == 0 AND file_download_count == 0`.
- auth: `int(5·log2(1 + success_count))`
- command volume: `min(3, command_count // 3)`
- **command quality** (`min(4)`): credential-access +3, destructive +2, lateral-cmd +1
  - Per-session path: regex over `commands` (constants `_CRED_PATTERNS`, `_DESTRUCTIVE_PATTERNS`, `_LATERAL_PATTERNS`)
  - IP-aggregate path: reads pre-computed `command_quality_tags` (commands not re-aggregated)
- file ingress: `min(3, file_download_count)`

**6 · exfiltration (WHAT, max 8)** — egress volume.
`min(8, int(2·log10(1 + KB)))` from `exfil_bytes`. 0 → "no data egress".

**7 · lateral_movement (WHAT, max 10)** — spread & escalation.
- CVE exploit +4
- SMB share enum +2; epmapper prescan +2
- ≥ 3 honeypots hit +2, ≥ 2 +1
- critical destination port (`{445, 1433, 3306, 3389, 5432, 27017, 6379, 9200}`) +2

**8 · malware (HOW, max 12)** — additive YARA + VT.
- YARA severity → pts (critical 6, high 4, medium 2, low 1); take the **max** across matched rules. Legacy `List[str]` treated as medium severity.
- VT tiers: ≥ 20 engines → 6, ≥ 10 → 4, ≥ 1 → 2

**9 · mitre_sophistication (HOW, max 12)** — breadth of TTPs.
- `min(6, len(set(techniques)))`
- kill-chain stage: `min(4, stage // 2)`
- distinct tactics: `min(2, max(0, n_tactics - 1))`
- accepts technique IDs as strings or `{id|technique_id}` dicts

### Composition

```python
score   = min(100, round(sum_of_points))                  # final 0–100
level   = risk_level(score)                               # from risk_thresholds
confidence = "HIGH" if active >= 5 else "MEDIUM" if active >= 3 else "LOW"
```

`active` = number of signals with `points > 0`.

### Thresholds ([risk_thresholds.py](../forensic-engine/risk_thresholds.py))

```
# Label cutoffs (v2.0 — recalibrated for 9-signal scorer)
CRITICAL = 70    (was 80)
HIGH     = 45    (was 60)
MEDIUM   = 25    (was 40)
LOW      = 10    (was 20)

# Operational thresholds — DECOUPLED from labels
ALERT_INDEX_MIN  = 40   # index alerts at this score
ALERT_NOTIFY_MIN = 60   # send WhatsApp/email at this score
PROFILE_RISK_MIN = 50   # run LLM profiler at this score
```

Operational thresholds are independent integers — *not* derived from `HIGH` — so future cutoff tweaks won't accidentally spike API costs.

### Output shape

```python
@dataclass
class SignalDetail:
    points: float
    max_points: int
    label: str
    category: str         # "who" | "what" | "how"
    detail: str           # human one-liner
    evidence: dict        # signal-specific structured evidence
    skipped: bool         # True if precondition failed (e.g. private IP for reputation)
    skip_reason: str | None

@dataclass
class ScoreResult:
    risk_score: int
    risk_level: str       # CRITICAL/HIGH/MEDIUM/LOW/INFO
    confidence: str       # HIGH/MEDIUM/LOW
    score_version: str    # "2.0.0"
    scored_at: str        # ISO timestamp
    scorer_mode: str      # "session" | "ip_aggregate"
    signal_breakdown: dict[str, dict]   # name -> SignalDetail.to_dict()
    active_signals: int
    sessions_aggregated: int | None     # ip_aggregate only
```

`signal_breakdown` is what lands in `forensic_sessions.enrichment_data.signal_breakdown` and `ip_risk_scores.signal_breakdown` JSONB.

---

## 8 · Phase 9 deep-dive — unified per-IP scoring

A session represents a single connection. An **attacker** is an IP that may have hundreds of sessions across multiple honeypots. Phase 9 collapses all that into one score per IP.

### Why it's separate from Phase 3
- Phase 3 answers: *"How bad was this one session?"*
- Phase 9 answers: *"How dangerous is this attacker overall?"*

A single SSH brute-force session looks LOW. The same IP doing 50 such sessions across SSH + SMB + HTTP looks very different.

### How `score_ip(ip, sessions, enrichment)` works

```python
# 1. Empty input → INFO result (idempotent: no sessions = no signals)
if not sessions:
    return _empty_ip_result()

# 2. Build a synthetic "super-session" that aggregates across sessions

# WHO fields from IP-level enrichment (reputation, threat_summary, geo, infra)
super_session = {
    "abuse_score":   reputation["abuse_score"],
    "is_tor":        threat["is_tor"],
    "is_bogon":      threat["is_bogon"],
    "shodan_vulns":  infra["vulns"],
    "geo_country_code": geo["country_code"],
    # … and so on
    "previously_seen":   any(s["previously_seen"] for s in sessions),
    "previous_sessions": max(s["previous_sessions"] for s in sessions),
    "is_private":        False,    # gated upstream
}

# WHAT fields — aggregate volume across sessions
super_session["login_attempts"]      = sum(...)
super_session["attack_velocity"]     = max(...)
super_session["success_count"]       = sum(...)
super_session["command_count"]       = sum(...)
super_session["exfil_bytes"]         = sum(...)
super_session["file_download_count"] = sum(...)

# Command quality — UNION of per-session quality tags (raw commands not re-aggregated)
super_session["command_quality_tags"] = sorted(set(
    tag for s in sessions for tag in s.get("command_quality_tags", [])
))
super_session["commands"] = []   # so per-session regex path doesn't double-fire

# Honeypot diversity
distinct = sorted({s["honeypot_type"] for s in sessions})
super_session["honeypot_type"]      = "multi" if len(distinct) > 1 else distinct[0]
super_session["honeypot_types_hit"] = distinct

# Lateral movement — OR / MAX / UNION across sessions
super_session["smb_share_enum"]   = any(...)
super_session["epmapper_prescan"] = max(...)
super_session["exploit_cve"]      = sorted(set(union of CVE lists))
# destination_port: pick first critical port if any, else first port

# HOW — malware concat, MITRE union, kill-chain from max-stage session
super_session["yara_matches"]     = [union of all rules]
super_session["vt_malicious"]     = max(...)
super_session["mitre_techniques"] = [union of all techniques]
super_session["kill_chain_stage"] = max(...)
super_session["kill_chain_phase"] = phase_from_max_stage_session

# 3. Score the super-session
result = score_session(super_session)
result.scorer_mode         = "ip_aggregate"
result.sessions_aggregated = len(sessions)
return result
```

### Why `commands=[]` in the super-session
Per-session quality regex looks at command strings. At IP-aggregate level we don't re-aggregate the raw command list (it could be huge); instead we **union the already-computed quality tags** from each session's `signal_breakdown.compromise_depth.evidence.command_quality_tags`. The `_signal_compromise_depth` function detects this (`if precomputed_tags:` branch) and bypasses regex.

### Storage
`_store_unified_risk_score()` upserts into `ip_risk_scores` keyed on `source_ip UNIQUE`, with the full `signal_breakdown` JSONB, `confidence`, `active_signals`, `honeypots_hit` (array), `honeypot_summary` (per-type counts), `sessions_count`, and `enrichment_snapshot` (frozen geo/asn/abuse/Tor flags at scoring time).

---

## 9 · Database schema (PostgreSQL)

Schema file: [forensic-engine/db/schema.sql](../forensic-engine/db/schema.sql). All tables are in the `forenhive` database.

| Table | Key | Purpose |
|---|---|---|
| `ip_enrichment_cache` | `ip` | 24 h TTL cache of GeoIP / abuse / privacy / infrastructure |
| `file_analysis` | `sha256` | YARA matches + VT verdict per binary |
| `api_quota_status` | `api_name` | Cross-run rate-limit state (VT / AbuseIPDB / Shodan / IPLocate) |
| `forensic_sessions` | `session_id` | One row per attacker session — score, MITRE, narrative, `enrichment_data` JSONB |
| `ip_risk_scores` | `source_ip UNIQUE` | One row per attacker IP — unified score + 9-signal `signal_breakdown` |
| `forensic_timeline_events` | `id` PK, `es_doc_id UNIQUE` | Cross-honeypot unified event stream, ms precision |
| `forensic_iocs` | `id` PK, `(ioc_type, ioc_value, source_ip) UNIQUE` | Deduplicated indicators of compromise |
| `forensic_chain_of_custody` | `id` PK, `session_id UNIQUE` | SHA-256 sealed record + hash chain |
| `forensic_coc_batches` | `id` PK | Merkle root + RFC 3161 TSA response per sealing run |
| `suspect_profiles` | `id` PK, `source_ip UNIQUE` | LLM behavioral profile JSONB |
| `forensic_alerts` | `id` PK | Sessions scoring ≥ `ALERT_INDEX_MIN` (also indexed to ES) |

Important indices:
- `idx_sessions_ip_time(source_ip, started_at DESC)` — Phase 9 lookup
- `idx_sessions_risk_score(risk_score DESC)` — dashboard top-N
- `idx_sessions_started_at(started_at DESC)` — windowed queries
- `idx_ip_risk_score(risk_score DESC)` — IP top-N

Version tracking:
- `forensic_sessions.score_version VARCHAR(16)` — populated by `_session_row` (defaults to `SCORE_VERSION` if not set)
- `ip_risk_scores.score_version VARCHAR(16)` — populated by `_store_unified_risk_score`

---

## 10 · External dependencies & graceful degradation

Each external service has a clear failure mode. The engine **never crashes** on an external outage; it records the gap and proceeds.

| Service | What if it's down | Where you'll see it |
|---|---|---|
| **Elasticsearch** | Engine aborts the run (it's the data source) | `Elasticsearch unreachable — aborting full analysis` |
| **PostgreSQL** | Engine aborts; writers raise | `wait_for_postgres` retries on boot |
| **Ollama (Mistral)** | MITRE narrative falls back to a deterministic 1-sentence summary; profiler returns `confidence=0.0` minimal profile | `Ollama unreachable (http://…)` warning |
| **AbuseIPDB** | `reputation` signal skipped; row has no abuse_score | Quota state in `api_quota_status` |
| **Shodan InternetDB** | `infrastructure` block empty; no vulns/ports | Logged as warning |
| **IPLocate** | `privacy` block empty; Tor/VPN/bogon all False | Logged as warning |
| **VirusTotal** | YARA-only verdict; `vt_malicious=0`; `vt_was_available=False` propagated into enrichment | `_network_dead` flag inside `virustotal.py` |
| **freetsa.org (RFC 3161 TSA)** | Sealing proceeds with `tsa_status='unavailable'`; local Merkle integrity is intact, external notarization is deferred | `TSA status=error` log line |
| **MaxMind GeoLite2** | Ships with the image; should never fail. If missing, geo fields are empty. | `GeoIP databases not available` |
| **Twilio (WhatsApp)** | Alert indexing still happens; just no message sent | Logged warning |

Quota tracking is **persistent across runs** via `api_quota_status`. An exhausted API stays exhausted until midnight UTC (configurable per API) or until manually reset with `--quota-reset`.

---

## 11 · Chain of custody — legal-grade integrity

[chain_of_custody.py](../forensic-engine/chain_of_custody.py) implements a three-layer scheme that maps to standard digital-forensics expectations.

### Layer 1 — Per-record SHA-256
Each unsealed `forensic_sessions` row is serialized to a **canonical JSON** dict (sorted keys, deterministic ordering, only forensic-relevant columns: `session_id, honeypot_type, source_ip, started_at, ended_at, risk_score, mitre_techniques, enrichment_data, kill_chain_phase, kill_chain_stage, primary_technique, forensic_narrative`) and hashed.

### Layer 2 — Hash chain
Each record stores the previous record's hash (`prev_hash`). Altering any session row breaks the chain at that point and every subsequent record — detectable in O(n) by [verify_coc.py](../forensic-engine/verify_coc.py).

### Layer 3 — Merkle root + RFC 3161 timestamp
All record hashes in one sealing run are aggregated into a binary Merkle tree (odd-level nodes duplicate-last). The single root hash is submitted to a public Time Stamping Authority (`freetsa.org` by default, configurable via `TSA_URL`, 15 s timeout). The TSA returns a signed DER-encoded token binding the Merkle root to a certified UTC timestamp, stored as `BYTEA` in `forensic_coc_batches.tsa_response`.

If the TSA is unreachable, `tsa_status='unavailable'` is recorded — local integrity remains; external notarization can be re-attempted later.

### Verification
`verify_coc.py` is **deliberately dependency-minimal** so it can be run by a third-party auditor without the full engine. It re-derives all three layers from current DB state and exits non-zero on the first mismatch. Wire it into CI to detect tampering.

---

## 12 · Configuration (environment variables)

Loaded from [.env](../.env) or container env. Defined in [config.py](../forensic-engine/config.py).

### Required
- `PG_HOST`, `PG_DB`, `PG_USER`, `PG_PASSWORD` — PostgreSQL connection
- `ES_HOSTS` (or `ES_URL`), `ES_INDEX` — Elasticsearch endpoint and pattern (`honeypot-logs-*`)

### LLM (Ollama)
- `OLLAMA_HOST` (default `forenhive-ollama`), `OLLAMA_PORT` (`11434`)
- `OLLAMA_MODEL` (`mistral`)
- `OLLAMA_TIMEOUT_SEC` (`300`)

### External APIs (optional but recommended)
- `ABUSEIPDB_KEY` — AbuseIPDB reputation
- `VIRUSTOTAL_KEY` — VT v3 file lookup
- `SHODAN_KEY` — Shodan host lookup (InternetDB doesn't need a key)

### Scheduler
- `ENGINE_INTERVAL_MINUTES` (default 1440 = 24 h; live config 5 min)

### Operational
- `ALERT_INDEX_MIN`, `ALERT_NOTIFY_MIN`, `PROFILE_RISK_MIN` (also defined in [risk_thresholds.py](../forensic-engine/risk_thresholds.py); env overrides if present)
- `TSA_URL` — RFC 3161 timestamping authority (default `freetsa.org`)
- `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_WHATSAPP_FROM`, `TWILIO_WHATSAPP_TO` — WhatsApp alerts

---

## 13 · Operations: run, verify, troubleshoot

### Run

```bash
# Full pipeline, 24h window (inside container)
docker exec forenhive-forensic-engine python engine.py --hours 24

# One-shot, detached, with LLM disabled (fast — for scoring validation)
docker exec -d -e OLLAMA_HOST=disabled forenhive-forensic-engine \
    sh -c 'python -u engine.py --hours 24 > /tmp/run.log 2>&1'

# Single phase
docker exec forenhive-forensic-engine python engine.py --score-only --hours 24

# Initialize schema
docker exec forenhive-forensic-engine python engine.py --init-db

# Check external API quota state
docker exec forenhive-forensic-engine python engine.py --quota-status

# Reset a stuck quota
docker exec forenhive-forensic-engine python engine.py --quota-reset virustotal
```

### Verify

```bash
# Unit tests
cd forensic-engine && python3 -m pytest tests/test_risk_score.py -q   # 76 pass
cd backend        && python3 -m pytest tests/test_risk_score.py -q   # 34 pass

# Per-session consistency (every row's level must match risk_thresholds(score))
docker exec -i forenhive-postgresql psql -U forenhive -d forenhive -c "
  SELECT risk_score, enrichment_data->>'risk_level' lvl,
         (enrichment_data->>'active_signals') IS NOT NULL has_active,
         score_version, count(*)
  FROM forensic_sessions
  GROUP BY 1,2,3,4 ORDER BY 1 DESC;"
# Expected: lvl matches risk_thresholds(risk_score), has_active=t, score_version=2.0.0

# Per-IP aggregate sanity
docker exec -i forenhive-postgresql psql -U forenhive -d forenhive -c "
  SELECT source_ip, risk_score, risk_level, score_version,
         (SELECT count(*) FROM jsonb_object_keys(signal_breakdown)) n_sig
  FROM ip_risk_scores ORDER BY risk_score DESC;"
# Expected: n_sig = 9, level matches score, score_version = 2.0.0

# Chain-of-custody integrity (third-party-runnable)
docker exec forenhive-forensic-engine python verify_coc.py
# Exits 0 on success, non-zero on tampering
```

### Troubleshoot

| Symptom | Likely cause | Action |
|---|---|---|
| `Elasticsearch unreachable — aborting` | ES container down or `ES_HOSTS` wrong | `docker ps`, check `ES_HOSTS` env |
| Phase 3 logs nothing for minutes | LLM narrative (Ollama) is slow (~15 s per session × N) | Disable: `-e OLLAMA_HOST=disabled` for fast scoring runs |
| `score_version=2.0.0` but rows look old-shape | Stale rows from before image rebuild (the `_session_row` fallback stamps the column on every save) | Run one full re-score; it overwrites JSONB |
| Scores shifting between identical runs | Recidivism feedback — each run increments `previous_sessions` for repeat IPs | Expected; will settle when run on a fixed window |
| `TSA status=error` | `freetsa.org` unreachable / timed out | Local Merkle integrity is intact; re-seal later when TSA is up |
| `Quota exhausted` for VT/AbuseIPDB | Free-tier daily limit hit | Wait until midnight UTC, or `--quota-reset <api>` if you know better |
| `Batch save failed, falling back to per-row` | One bad row in a batch | Check the per-row error log; usually a JSON serialization issue |
| IP aggregate at 0/INFO despite many sessions | Synthetic data with no WHO/HOW signals (private IP + no abuse + no malware + no MITRE) | Expected for synthetic Kali traffic; real attackers will escalate |
| Empty `enrichment_data->>'active_signals'` | Row written by old code before EDIT D | Run one re-score; `_save_sessions_batch` will overwrite |

### After deploying code changes
The engine code is **baked into the Docker image** (`COPY . .` in Dockerfile), not bind-mounted. Host edits aren't live until you rebuild:

```bash
cd /home/pfe/forenhive
docker compose build forensic-engine
docker compose up -d forensic-engine
```

For temporary in-container testing without rebuild:
```bash
docker cp <file> forenhive-forensic-engine:/app/<file>
```
(ephemeral; reverts on `docker compose down` or `up -d`)

---

## 14 · Module reference

| File | Lines | Role |
|---|---:|---|
| [engine.py](../forensic-engine/engine.py) | 1468 | Orchestrator — 10 phases, CLI, ES scrolls, PG writes |
| [server.py](../forensic-engine/server.py) | 370 | Flask service + scheduler daemon thread |
| [config.py](../forensic-engine/config.py) | 83 | `.env` loader; endpoints + keys |
| [risk_score.py](../forensic-engine/risk_score.py) | 652 | 9-signal scorer (v2.0.0); `score_session` + `score_ip` |
| [risk_thresholds.py](../forensic-engine/risk_thresholds.py) | 30 | Label cutoffs + decoupled operational thresholds |
| [mitre_mapper.py](../forensic-engine/mitre_mapper.py) | 480 | Hybrid deterministic IDs + LLM narrative |
| [enricher.py](../forensic-engine/enricher.py) | 627 | GeoIP + AbuseIPDB + IPLocate + Shodan + WHOIS |
| [smb_analyzer.py](../forensic-engine/smb_analyzer.py) | 643 | Dionaea + Zeek SMB forensic fusion |
| [yara_scanner.py](../forensic-engine/yara_scanner.py) | 137 | YARA compilation + scan, severity from rule meta |
| [virustotal.py](../forensic-engine/virustotal.py) | 184 | VT v3 + quota awareness |
| [timeline_builder.py](../forensic-engine/timeline_builder.py) | 329 | ES → PG event normalization |
| [ioc_extractor.py](../forensic-engine/ioc_extractor.py) | 240 | Regex IoC extraction with dedup |
| [chain_of_custody.py](../forensic-engine/chain_of_custody.py) | 324 | SHA-256 + Merkle + RFC 3161 |
| [verify_coc.py](../forensic-engine/verify_coc.py) | 130 | Independent CoC verifier |
| [profiler.py](../forensic-engine/profiler.py) | 660 | LLM behavioral profiling |
| [quota_tracker.py](../forensic-engine/quota_tracker.py) | 229 | Persistent rate-limit state |
| [db/schema.sql](../forensic-engine/db/schema.sql) | 250+ | All tables + indices + the v2 migration |
| [db/init_db.py](../forensic-engine/db/init_db.py) | 60 | Idempotent schema bootstrap |
| [tests/test_risk_score.py](../forensic-engine/tests/test_risk_score.py) | 350 | 76 unit tests for the scorer |
| [yara_rules/](../forensic-engine/yara_rules/) | 10 files | Malware family signatures |

---

## 15 · Glossary

- **Session.** One contiguous attacker interaction with one honeypot. For Cowrie, identified by `session.id`. For Dionaea/Galah/Zeek, derived from `(source_ip, time_bucket)`.
- **WHO / WHAT / HOW.** The three signal buckets in v2.0.0. WHO = identity & trust (33 pts). WHAT = observed behavior (43 pts). HOW = capability & tooling (24 pts). Sums to 100.
- **MITRE technique.** An ATT&CK identifier like `T1110.001` (SSH brute force). The engine derives them deterministically from a 16-entry rule table — no LLM hallucination.
- **Kill-chain phase.** Lockheed Martin's 7-stage Cyber Kill Chain. The engine maps MITRE techniques to phases (reconnaissance, weaponization, delivery, exploitation, installation, command_and_control, actions_on_objectives).
- **Recidivism.** Whether an IP has been seen in prior sessions over a lookback window (`_query_recidivism`, 720 h default). Feeds the `threat_history` signal.
- **Chain of custody.** Cryptographic evidence that a forensic record hasn't been altered since sealing. Three layers: per-record SHA-256, hash chain, Merkle root + RFC 3161 TSA timestamp.
- **Merkle root.** A single hash that mathematically depends on every leaf hash in a batch. Used to prove inclusion without revealing the whole batch.
- **RFC 3161 / TSA.** The IETF standard for cryptographic timestamping. A Time Stamping Authority returns a signed token binding a hash to a certified UTC time — admissible as legal evidence.
- **Quota tracker.** A PG-backed cross-run state machine that remembers when each external API hit its rate limit and when it resets, so re-runs don't keep hammering an exhausted endpoint.
- **Phase 0 / 1 / 2a / 2b / 3 / 4 / 5 / 6 / 7 / 8 / 9.** The 10 ordered steps in `run_full_analysis`. Phase 0 (SMB) was added later but runs after Phase 1 because it depends on enrichment.
- **`SCORE_VERSION`.** The string `"2.0.0"` tagged on every row scored by the new model. Use it to filter v2 rows in dashboards: `WHERE score_version = '2.0.0'`.
- **`active_signals`.** Count of signals with `points > 0` for a given row. Drives confidence: ≥ 5 → HIGH, ≥ 3 → MEDIUM, else LOW.

---

**Document version:** 1.0 (engine version 2.0.0)
**Last updated:** 2026-05-22
**Maintainers:** ForenHive PFE 2025/2026 — Zeineb Benrhouma & Ismail Cherif
**See also:** [architecture.md](architecture.md) · [sprint3_audit_final.md](sprint3_audit_final.md) (v1 baseline) · [sprint3_audit_v2.md](sprint3_audit_v2.md) (v1 → v2 delta)
