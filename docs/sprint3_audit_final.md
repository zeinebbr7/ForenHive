# Sprint 3 — Forensic Engine · Complete Audit
**Project:** ForenHive · PFE 2025/2026 — ISET Radès (RSI), Standard Sharing Software (3S), Tunis
**Students:** Zeineb Benrhouma & Ismail Cherif
**Branch audited:** `zeineb` (HEAD `5f2c4cc`, 2026-04-16)
**Audit date:** 2026-04-17
**Scope:** `/home/pfe/forenhive/forensic-engine/` — 18 production modules, 2 db files, 10 YARA rule files, 6 250 lines of Python

---

## 1 · Executive overview

Sprint 3 builds the **forensic analysis layer** that sits between the ETL pipeline (Sprint 2, Elasticsearch) and the future FastAPI backend (Sprint 4). It is implemented as a standalone Python 3.11 CLI application (`engine.py`) orchestrating seven analysis phases. Its job is to turn raw honeypot logs into **admissible, criminally-profiled forensic evidence**: enriched IPs, scored sessions, MITRE-mapped kill chains, a tamper-evident event timeline, structured indicators of compromise, RFC 3161-sealed chain of custody, and LLM-generated attacker behavioral profiles.

The engine runs on demand (`docker exec forenhive-forensic-engine-dev python3 /app/engine.py --hours 24`) or per phase (`--enrich-only`, `--score-only`, `--profile-only`, etc.). It writes to two stores simultaneously — PostgreSQL (permanent audit trail, schema with 9 tables) and Elasticsearch (`forenhive-suspect-profiles`, `forenhive-smb-analysis`) — in accordance with the dual-storage principle defined in [docs/architecture.md](architecture.md).

**Current state (live, 2026-04-17 10:00 UTC):** 18 sessions scored and sealed across 6 unique attacker IPs, 24 normalized timeline events, 36 extracted IoCs, 18 chain-of-custody records signed against 1 Merkle root, and 7 LLM-generated suspect profiles (5 indexed in Elasticsearch). All 10 stack containers are up; Ollama serves `mistral:latest` (7.2 B · Q4_K_M) for LLM inference.

**What is complete:** all seven pipeline phases, schema migration, idempotent writers, graceful degradation for missing APIs, offline GeoIP, cross-run persistent quota tracking, and a standalone chain-of-custody verifier (`verify_coc.py`). **What is not:** the FastAPI backend (Sprint 4), React dashboard (Sprint 5), Nginx SSL termination, and true public-internet honeypot traffic — current data is synthetic (injected Kali scenarios).

---

## 2 · Position in the 5-layer architecture

```
C1 Honeypots  →  C2 ETL Pipeline     →  C3 Forensic Engine  →  C4 Backend (TODO)  →  C5 Frontend (TODO)
 Cowrie            Filebeat              ┌─────────────────┐      FastAPI / JWT        React / Attack map
 Dionaea           Logstash              │ engine.py · 7   │
 Galah             Elasticsearch ────────│ phases · Ollama │───── PostgreSQL · ES
 Zeek              (honeypot-logs-*)     └─────────────────┘      (forensic_* + profiles)
```

The forensic engine is the **only** component in Sprint 3 that is both a **consumer** (reads ES) and a **producer** (writes PG + ES indices). It is packaged as a Docker image (`forenhive-forensic-engine-dev`), but is not part of the live ingestion loop — it is executed in batch.

**Networks:** `backend-net` only (no exposure to `honeypot-net`). **Dependencies:** Elasticsearch, PostgreSQL, Ollama, three optional third-party APIs (AbuseIPDB, Shodan, VirusTotal), one optional RFC 3161 TSA (`freetsa.org`).

---

## 3 · End-to-end data flow

```
  honeypot-logs-YYYY.MM.dd            ┌── PG: ip_enrichment_cache  (24 h TTL)
  ┌──────────────────┐                │
  │ Cowrie, Dionaea, │                ├── PG: file_analysis        (YARA + VT)
  │ Galah, Zeek      │                │
  └────────┬─────────┘                ├── PG: forensic_sessions    (risk + MITRE)
           │  ES scroll API           │
           ▼                          ├── PG: forensic_timeline_events (unified)
    ┌─────────────────┐               │
    │   engine.py     │─── writes ───►├── PG: forensic_iocs        (url/ip/hash/…)
    │  (7 phases)     │               │
    └──────┬──────────┘               ├── PG: forensic_chain_of_custody
           │                          │      + forensic_coc_batches (Merkle + TSA)
           │  LLM prompt              │
           ▼                          ├── PG: suspect_profiles     (JSONB)
   ┌────────────────┐                 │
   │ Ollama/Mistral │                 └── ES: forenhive-suspect-profiles
   │  (profiler +   │                        + forenhive-smb-analysis
   │   MITRE narr.) │
   └────────────────┘
```

Every writer is **idempotent**: sessions keyed on `session_id`, timeline events on the ES document `_id`, IoCs on `(ioc_type, ioc_value, source_ip)`, CoC records on `session_id UNIQUE`, profiles on `source_ip UNIQUE`. Re-running the same window does not duplicate rows.

---

## 4 · Module inventory (by role)

| Role | File | Lines | Purpose |
|---|---|---|---|
| **Orchestrator** | [engine.py](../forensic-engine/engine.py) | 937 | Coordinates 7 phases, CLI flags, ES scrolls, PG writes |
| **Config** | [config.py](../forensic-engine/config.py) | 70 | `.env` loader; ES/PG/Ollama endpoints, API keys, YARA dir |
| **DB schema** | [db/schema.sql](../forensic-engine/db/schema.sql) | 158 | 9 tables + indices + upsert constraints |
| **DB init** | [db/init_db.py](../forensic-engine/db/init_db.py) | 60 | Idempotent schema bootstrap, retry-on-boot |
| **Phase 1 — Enrichment** | [enricher.py](../forensic-engine/enricher.py) | 351 | GeoIP (MaxMind), AbuseIPDB, IPLocate (Tor/VPN), Shodan, WHOIS |
| **Phase 2a — YARA** | [yara_scanner.py](../forensic-engine/yara_scanner.py) | 139 | Scans `/opt/dionaea/var/lib/dionaea/binaries` against 9 rule sets |
| **Phase 2b — VirusTotal** | [virustotal.py](../forensic-engine/virustotal.py) | 186 | SHA-256 → v3 API; 4 req/day free tier; cache + quota aware |
| **Phase 3 — Scoring** | [risk_score.py](../forensic-engine/risk_score.py) | 955 | 18-signal deterministic 0–100 score + narrative + MITRE |
| **Phase 3 — MITRE** | [mitre_mapper.py](../forensic-engine/mitre_mapper.py) | 421 | Hybrid: deterministic 16-technique dictionary + LLM narrative |
| **Phase 3 — SMB** | [smb_analyzer.py](../forensic-engine/smb_analyzer.py) | 638 | Dionaea SQLite + Zeek NTLM fusion → `forenhive-smb-analysis` |
| **Phase 4 — Timeline** | [timeline_builder.py](../forensic-engine/timeline_builder.py) | 329 | ES → PG, 4 honeypot normalizers, ms precision |
| **Phase 5 — IoC** | [ioc_extractor.py](../forensic-engine/ioc_extractor.py) | 238 | Regex scan on timeline → 10 IoC types (url/ip/hash/cve/…) |
| **Phase 6 — Chain of custody** | [chain_of_custody.py](../forensic-engine/chain_of_custody.py) | 294 | SHA-256 chain + Merkle root + RFC 3161 TSA |
| **Phase 7 — Profiler** | [profiler.py](../forensic-engine/profiler.py) | 642 | FBI-BAU LLM behavioral profile (4-section prompt) |
| **CoC verifier** | [verify_coc.py](../forensic-engine/verify_coc.py) | 130 | Independent replay; exit 1 on tampering |
| **Quota tracker** | [quota_tracker.py](../forensic-engine/quota_tracker.py) | 187 | Persistent PG-backed rate-limit guard (VT/AbuseIPDB/…) |
| Legacy — deprecated | [mitre_llm.py](../forensic-engine/mitre_llm.py) | 129 | Standalone pre-hybrid MITRE mapper; **dead code** |
| Legacy — deprecated | [ollama_mitre.py](../forensic-engine/ollama_mitre.py) | 304 | Old pure-LLM mapper; **still imported but superseded** |
| Legacy — deprecated | [virustotal_scanner.py](../forensic-engine/virustotal_scanner.py) | 82 | Pre-integration VT script; **not used by engine** |
| YARA rules | [yara_rules/](../forensic-engine/yara_rules/) | 9 files | Mirai, WannaCry, LockBit/BlackCat/Clop, AsyncRAT/QuasarRAT, XMRig, Emotet, shells, SSH brute |
| Legacy YARA | [yara-rules/malware.yar](../forensic-engine/yara-rules/malware.yar) | 1 file | EICAR + generic patterns; **secondary directory** |

### What each module consumes and produces

| Module | Reads from | Writes to |
|---|---|---|
| `enricher.py` | ES `honeypot-logs-*`, MaxMind GeoLite2 files, 4 HTTP APIs | PG `ip_enrichment_cache` |
| `yara_scanner.py` | Dionaea binaries dir | PG `file_analysis` |
| `virustotal.py` | PG `file_analysis` (hashes), VT v3 API | PG `file_analysis` (enriched), PG `api_quota_status` |
| `risk_score.py` | Session aggregates (from engine), enrichment, SMB index | Return dict only (persisted by `engine.py`) |
| `mitre_mapper.py` | Session aggregates, Ollama | Return dict only |
| `smb_analyzer.py` | Dionaea SQLite, Zeek NTLM logs, PG enrichment | ES `forenhive-smb-analysis` |
| `timeline_builder.py` | ES `honeypot-logs-*` | PG `forensic_timeline_events` |
| `ioc_extractor.py` | PG `forensic_timeline_events` | PG `forensic_iocs` |
| `chain_of_custody.py` | PG `forensic_sessions` (unsealed) | PG `forensic_chain_of_custody` + `forensic_coc_batches` |
| `profiler.py` | PG sessions, timeline, enrichment; ES SMB + similar profiles; Ollama | PG `suspect_profiles`, ES `forenhive-suspect-profiles` |
| `verify_coc.py` | PG CoC tables | stdout (exit 0/1) |

---

## 5 · The 7-phase pipeline (engine.py walkthrough)

`ForensicEngine.run_full_analysis(hours_back)` calls seven methods in fixed order. Each phase is also exposed as a CLI flag for isolated execution.

| # | Phase | Method | CLI flag | Output target |
|---|---|---|---|---|
| 1 | IP enrichment | `run_enrichment` | `--enrich-only` | PG `ip_enrichment_cache` |
| 2a | YARA scan | `run_yara_scan` | `--yara-only` | PG `file_analysis` |
| 2b | VirusTotal lookup | `run_vt_from_es` | (implicit after 2a) | PG `file_analysis` |
| 3 | Session scoring + MITRE | `run_session_scoring` | `--score-only` | PG `forensic_sessions` |
| 4 | Timeline build | `run_timeline_build` | `--timeline-only` | PG `forensic_timeline_events` |
| 5 | IoC extraction | `run_ioc_extraction` | `--ioc-only` | PG `forensic_iocs` |
| 6 | Chain of custody | `run_chain_of_custody` | `--coc-only` | PG `forensic_chain_of_custody` + `forensic_coc_batches` |
| 7 | Attacker profiling | `run_profiling` | `--profile-only` | PG `suspect_profiles` + ES `forenhive-suspect-profiles` |

**Phase 1 — Enrichment.** Pulls unique `source.ip` from ES over `hours_back`, filters private IPs (classified by `_classify_private_ip` as `loopback` / `docker_bridge` / `corporate_internal`), consults `ip_enrichment_cache` (24 h TTL), and for misses runs five parallel lookups: MaxMind GeoLite2 City + ASN (offline), AbuseIPDB (requires `ABUSEIPDB_KEY`), IPLocate free API (Tor/VPN/proxy flags), Shodan InternetDB (open ports, tags), RDAP WHOIS. Quota exhaustion is checked before each external call via `quota_tracker`.

**Phase 2a — YARA.** Compiles every `.yar` file in `yara_rules/` once per run (fail-soft on bad rules). Walks Dionaea's binaries directory, hashes each file (SHA-256 in 64 KB chunks), and persists matches to `file_analysis` regardless of hit count (enables negative caching). **Current status:** 0 files in `file_analysis` — Dionaea has not captured any malware samples yet because honeypots are not internet-facing.

**Phase 2b — VirusTotal.** Takes SHA-256 hashes produced by Phase 2a (and any `file.hash.sha256` from Cowrie downloads) and calls `v3/files/{sha256}`. Free tier is 4 req/day — `virustotal.py` self-paces at 0.25 s/req and aborts the batch on first network error (sets `_network_dead`). HTTP 429 is recorded in `api_quota_status` with `reset_at = next UTC midnight`.

**Phase 3 — Scoring + MITRE.** Aggregates per-session data across Cowrie (by `session.id`), Dionaea and Galah (by `source.ip`). For each session: `risk_score.calculate_risk_score()` returns a fully structured dict (score, level, narrative, MITRE, IoCs, recommended actions). `MitreMapper.map_session()` overrides/extends the techniques via deterministic rules and optionally calls Ollama for a 2-sentence narrative. Results are persisted to `forensic_sessions`.

**Phase 4 — Timeline.** Scrolls ES in batches of 1 000 documents, routes each event through one of four normalizers (`_norm_cowrie`, `_norm_dionaea`, `_norm_galah`, `_norm_zeek`), and upserts into `forensic_timeline_events` keyed on `es_doc_id UNIQUE`. Field extraction supports both nested (`a.b`) and flat-dotted ES schemas.

**Phase 5 — IoC extraction.** Regex-scans the timeline for ten IoC types (`url`, `domain`, `ipv4_external`, `sha256`, `md5`, `cve`, `user_agent`, `cmdline`, `file_path`, `email`, `http_path`), deduplicates by `(ioc_type, ioc_value, source_ip)`, and tracks `first_seen`, `last_seen`, `occurrences`, `honeypot_types` via merge-on-upsert.

**Phase 6 — Chain of custody.** Three-stage sealing:
1. Build a canonical JSON representation of each unsealed session (sorted keys, only forensic-relevant columns) → SHA-256.
2. Link records into a hash chain (`prev_hash` = previous record's `record_hash`).
3. Build a Merkle root from all batch hashes and submit it to the RFC 3161 TSA (`freetsa.org`, 15 s timeout). Raw TSA response stored as `BYTEA`, status recorded as `sealed` / `unavailable`.

**Phase 7 — Profiler.** For each distinct scored IP, builds a 4-section detective prompt (system role, criminology framework, evidence XML, reference cases), calls Ollama/Mistral at `T=0.3, num_ctx=8192, timeout=300 s`, parses JSON, and stores the profile dual-sink (PG `suspect_profiles` keyed on `source_ip UNIQUE`, ES `forenhive-suspect-profiles/_doc/profile-{ip}`). On Ollama failure, retries once; second failure returns a minimal `confidence=0.0` profile.

---

## 6 · Database schema (PostgreSQL)

Schema file: [db/schema.sql](../forensic-engine/db/schema.sql) · 9 tables.

| Table | Primary key | Purpose | Live rows |
|---|---|---|---:|
| `ip_enrichment_cache` | `ip` | 24 h TTL cache of GeoIP/abuse/privacy/infrastructure | 3 |
| `file_analysis` | `sha256` | YARA matches + VT verdict per binary | 0 |
| `forensic_sessions` | `session_id` | One row per attacker session; scored + MITRE-mapped | 18 |
| `api_quota_status` | `api_name` | Persistent rate-limit state across runs | 0 |
| `forensic_timeline_events` | `id` (serial), unique `es_doc_id` | Unified cross-honeypot event stream per IP | 24 |
| `forensic_iocs` | `id`, unique `(ioc_type, ioc_value, source_ip)` | Deduplicated indicators of compromise | 36 |
| `forensic_chain_of_custody` | `id`, unique `session_id` | SHA-256 sealed record + hash chain | 18 |
| `forensic_coc_batches` | `id` | Merkle root + RFC 3161 TSA response per sealing run | 1 |
| `suspect_profiles` | `id`, unique `source_ip` | LLM behavioral profile (JSONB) | 7 |

The `suspect_profiles` unique index on `source_ip` and the `updated_at` column were added during profiler integration (commit HEAD, uncommitted on `zeineb`).

---

## 7 · Risk scoring — the 18 signals

`risk_score.py` (`calculate_risk_score(session, enrichment, smb, vt_available)`) composes the final 0–100 score from 18 independent signals. Private-IP attacker sessions get a **behavioral ×2 multiplier** on `login_volume`, `commands`, `exfiltration`, and `malware_yara` to reflect lateral-movement / insider-threat context.

| # | Signal | Max pts | Trigger |
|---:|---|---:|---|
| 1 | `reputation` | 40 | AbuseIPDB abuse_score × 0.40 (public IPs only) |
| 2 | `reputation_volume` | 10 | log-scale total_reports (3 / 6 / 10) |
| 3 | `anonymization` | 10 | Tor / VPN / proxy flag in IPLocate |
| 4 | `attacker_infrastructure` | 15 | Shodan vulns (10) + hosting/VPS ASN (5) |
| 5 | `malware_yara` | 45 | Base 12 (20 if high-severity family) × private-IP multiplier; +5 if VT unavailable |
| 6 | `malware_vt` | 15 | 8 pts if 1–10 AV engines, 15 if >10 |
| 7 | `login_volume` | 20 | 2 / 5 / 10 pts for attempt tiers; ×2 private |
| 8 | `successful_compromise` | 25 | `success_count > 0` → T1078 Valid Accounts |
| 9 | `critical_port` | 5 | target port in {22, 23, 445, 1433, 3306, 5432, 6379, 9200, 27017, 2375} |
| 10 | `commands` | 10 | 2 / 5 pts for executed command tiers; ×2 private |
| 11 | `exfiltration` | 10 | 2 / 5 pts for transfer volume; ×2 private |
| 12 | `attack_velocity` | 5 | ≥ 2 attempts/s AND > 10 total — automation signal |
| 13 | `smb_share_enum` | 30 | NetShareEnum (SRVSVC opnum 15) observed → T1135 |
| 14 | `smb_epmapper` | 15 | RPC endpoint mapper pre-scan → T1046 |
| 15 | `exploit_cve` | 40 | Known CVE probe (MS08-067, EternalBlue, etc.) → T1190 |
| 16 | `multi_honeypot` | 10 | attacker hit > 1 honeypot type → T1595 |
| 17 | `recidivism` | 10 | IP seen in prior session (720 h lookback) |
| 18 | `temporal_anomaly` | 5 | off-hours attack, 22:00–06:00 Africa/Tunis |

**Risk level mapping:** 80+ CRITICAL · 60–79 HIGH · 40–59 MEDIUM · 20–39 LOW · 0–19 INFO.

The function also returns `attribution` (country, ASN, hostnames, likely-compromised flag, attacker profile), `iocs` (hashes, tags, CVEs, ports), a 4–6 sentence `narrative`, and a prioritized SOC `recommended_actions` list.

**Live observation:** on the 18 current sessions, top scorer is `185.191.171.12` at 70 (HIGH); the other five IPs range 20–27 (LOW). This matches the synthetic Kali-injected scenario where one IP simulates an advanced attacker and five others simulate opportunistic scanning.

---

## 8 · LLM integration (Ollama / Mistral)

Two modules use Ollama, in different styles:

**`mitre_mapper.py` — hybrid deterministic + LLM.** Techniques are computed from a 16-entry dictionary (T1110.001, T1078, T1190, T1021.002, T1486, T1595.002, T1046, T1210, T1552.001, T1059.004, T1105, T1496, T1071.001, T1592, T1110.003, T1135). The LLM is only asked for a 2-sentence forensic narrative — never for technique IDs. This rules out hallucinated T-IDs and guarantees `confidence=1.0` on the MITRE map. If Ollama is unavailable, a fallback narrative is generated deterministically. Model: `mistral:latest` (7.2 B · Q4_K_M, 4.1 GB).

**`profiler.py` — full LLM profiling.** The prompt is structured into four sections totaling ≈3 000 tokens:

1. **System role** (≈200 tokens) — FBI Behavioral Analysis Unit profiler persona, JSON-only output contract, schema definition.
2. **Criminology framework** (≈400 tokens) — decision rules for *organized vs. disorganized*, sophistication tiers (amateur / intermediate / expert), nine primary objectives, disguise detection (Tor / VPN / proxy as forensic-awareness signal), kill-chain escalation logic, signature vs. modus operandi.
3. **Evidence** (≈800–1 500 tokens, XML-delimited) — session metadata, enrichment, timeline category counts, SMB data, MITRE techniques, risk score.
4. **Reference cases** (≈600–900 tokens, optional) — up to 5 similar past profiles retrieved from `forenhive-suspect-profiles` via an ES `bool/should` query over MITRE techniques (weight 3), ASN (2), country (1), and risk score ±15 (1).

Output schema (enforced by prompt, validated on parse):

```json
{
  "source_ip": "…",          "sophistication": "amateur|intermediate|expert|unknown",
  "confidence": 0.0-1.0,     "primary_objective": "credential_harvesting|botnet_recruitment|…",
  "secondary_objective": "…|null",
  "behavioral_traits": ["…"], "organized_score": 0.0-1.0,
  "disguise_used": bool,     "disguise_type": "tor|vpn|proxy|none",
  "escalation_detected": bool, "mitre_techniques": ["T…"],
  "dominant_tactic": "…",    "kill_chain_phase": "…",
  "signature_indicators": ["…"], "similar_past_cases": 0-5,
  "risk_score": 0-100,       "detective_narrative": "3-5 sentence paragraph"
}
```

**Runtime cost:** ≈115–200 s per profile on CPU with Mistral 7B (confirmed empirically on 172.16.50.25 at 198 s). Initial `OLLAMA_TIMEOUT_SEC=120` was raised to **300 s** after live testing produced two timeouts in a row on the same IP.

---

## 9 · Chain of custody — legal-grade sealing

`chain_of_custody.py` implements a three-layer integrity scheme that maps to standard digital-forensics expectations.

**Layer 1 — Per-record SHA-256.** Every sealed `forensic_sessions` row is serialized to a canonical JSON dict (sorted keys, deterministic ordering, only forensic-relevant columns: `session_id, honeypot_type, source_ip, started_at, ended_at, risk_score, mitre_techniques, enrichment_data, kill_chain_phase, kill_chain_stage, primary_technique, forensic_narrative`) and hashed.

**Layer 2 — Hash chain.** Each record stores the previous record's hash (`prev_hash`). Altering any session row would break the chain at that point and at every subsequent record — detectable in O(n) by `verify_coc.py`.

**Layer 3 — Merkle root + RFC 3161.** All record hashes in a sealing run are aggregated into a binary Merkle tree (odd-level nodes duplicate-last), producing a single root hash that is submitted to a public Time Stamping Authority. The TSA returns a signed DER-encoded token binding the Merkle root to a certified UTC timestamp; this token is stored as `BYTEA` in `forensic_coc_batches.tsa_response`. Default TSA is `freetsa.org` (free, public); configurable via `TSA_URL`. When the TSA is unreachable, sealing proceeds with `tsa_status='unavailable'` — local integrity is preserved, external notarization is deferred.

**Verification** is a separate process (`verify_coc.py`) that re-computes all three layers from the current database state and exits non-zero on the first mismatch. It is deliberately dependency-minimal so it can be run by a third party without the full engine.

**Live state:** 18 sessions sealed, 1 batch, Merkle root stored, TSA status visible via `verify_coc.py`.

---

## 10 · Live system state (snapshot, 2026-04-17 10:00 UTC)

**Docker containers — 10/10 up:**

| Container | Uptime | Role |
|---|---|---|
| `forenhive-postgresql` | 4 days | Forensic evidence store |
| `forenhive-elasticsearch` | 3 days | Honeypot logs + profiles |
| `forenhive-ollama` | 41 h | LLM inference (Mistral 7B + Phi3 mini) |
| `forenhive-forensic-engine-dev` | 2 days | Engine runtime |
| `forenhive-galah` | 7 days | HTTP honeypot (LLM-powered) |
| `forenhive-filebeat` | 18 h | Log shipper |
| `forenhive-logstash` | 18 h | ECS normalization |
| `forenhive-cowrie` | 11 days | SSH / Telnet honeypot |
| `forenhive-zeek` | 11 days | Passive protocol analyzer |
| `forenhive-dionaea` | 11 days | Multi-protocol honeypot |

**PostgreSQL (`forenhive` db):** 9 forensic tables, 107 total rows. `forensic_sessions=18`, `forensic_chain_of_custody=18` (100 % sealed), `forensic_coc_batches=1`, `forensic_timeline_events=24`, `forensic_iocs=36`, `suspect_profiles=7`, `ip_enrichment_cache=3`, `file_analysis=0`, `api_quota_status=0`.

**Elasticsearch indices:** `honeypot-logs-2026.04.17` (7 478 docs, 1.2 MB), `honeypot-logs-2026.04.16` (141 docs), `forenhive-suspect-profiles` (5 profiles, 72.6 KB), `test-index` (leftover, safe to drop).

**Ollama models:** `mistral:latest` (7.2 B · Q4_K_M · 4.07 GB · last pulled 2026-03-25) · `phi3:mini` (3.8 B · Q4_0 · 2.03 GB · last pulled 2026-04-12).

**Attacker IPs under analysis (top 6 by session count):**

| IP | Sessions | Max risk | Kill-chain phases reached |
|---|---:|---:|---|
| `185.191.171.12` | 3 | 70 | delivery, lateral_movement |
| `118.25.6.39` | 3 | 27 | delivery, lateral_movement |
| `45.155.205.233` | 3 | 23 | delivery, lateral_movement |
| `172.16.50.25` | 3 | 20 | delivery, lateral_movement |
| `192.168.100.50` | 3 | 20 | delivery, lateral_movement |
| `10.0.50.25` | 3 | 20 | delivery, lateral_movement |

Every IP has been observed across all three session-bearing honeypots (Cowrie / Dionaea / Galah = 6 sessions each for the dataset, 3 × 6 = 18 total). Profiler output consistently classifies these IPs as **intermediate sophistication**, **primary objective = lateral_movement**.

---

## 11 · Authorship and what is still missing

### 11.1 · Authorship reconstruction

All commits are authored as a single shared account (`ForenHive <isetr.pfe@gmail.com>`), so individual attribution is inferred from **branch topology** and **commit messages** rather than `git blame`.

Two feature branches exist: `zeineb` (currently checked out) and `ismail` / `ismail2`. Commit `625744d` ("Merge zeineb into ismail") documents that Zeineb's work landed in the shared state via merge.

Based on commit message semantics and file grouping within each commit:

| Likely owner | Modules / areas | Evidence |
|---|---|---|
| **Ismail Cherif** | `enricher.py`, `virustotal.py`, `yara_scanner.py`, `yara_rules/`, initial `risk_score.py`, `ollama_mitre.py`, `smb_analyzer.py`, `config.py` scaffolding | Commits `6998ddb` ("AbuseIPDB enrichment engine"), `c670a59` ("YARA rules"), `f4ab9a2` ("VirusTotal hash lookup"), `f5473b8` ("sprint3 sans test" — initial scaffolding), `6039df7` ("optimisation pt1"), `025a49b` ("ollama") — the **ingestion / detection pipeline** (Phases 1–3) |
| **Zeineb Benrhouma** | `timeline_builder.py`, `ioc_extractor.py`, `chain_of_custody.py`, `verify_coc.py`, `mitre_mapper.py` hybrid redesign, schema migrations | Commit `0c72860` ("kol chay yi5dem") — single large commit adding all four forensic-evidence modules together; `5184341` ("changes in sprint 3") introducing `mitre_mapper.py`; merge marker `625744d` ("Merge zeineb into ismail") — the **forensic-evidence layer** (Phases 4–6) |
| **Claude Code (collaboration, this session)** | `profiler.py`, `engine.py` Phase 7 wiring, `suspect_profiles` unique-index migration | Not yet committed on any branch — currently uncommitted working-tree changes on `zeineb` |

This split is consistent with the project's design-document division of labor (Phase 1–3 = pipeline intake; Phase 4–6 = evidentiary layer; Phase 7 = behavioral analysis).

### 11.2 · Known gaps and broken / partial items

| Item | Severity | Notes |
|---|---|---|
| `file_analysis` has 0 rows | Expected | Honeypots are not internet-facing yet; Dionaea has not captured real malware |
| `api_quota_status` has 0 rows | Expected | No third-party API has hit its quota during testing |
| Deprecation warning from `elasticsearch-py` | Cosmetic | `profiler.py:187` uses `ignore=404` transport option; fix = `.options(ignore_status=404).get(...)` |
| `ollama_mitre.py` still imported | Dead code | Superseded by `mitre_mapper.py` hybrid; should be removed |
| `mitre_llm.py` | Dead code | Pre-hybrid standalone; not wired into `engine.py` |
| `virustotal_scanner.py` | Dead code | Early VT prototype; not wired into `engine.py` |
| Two YARA directories (`yara_rules/` + `yara-rules/`) | Minor | Legacy single-file `yara-rules/malware.yar` should be merged into `yara_rules/` and the hyphen-named directory deleted |
| `PROFILER_IMPLEMENTATION.md` / `PROFILER_TEST_REPORT.md` in repo root | Minor | Should live under `docs/` alongside this audit |
| Sprint 4 (FastAPI backend) | Not started | Empty placeholder files only |
| Sprint 5 (React frontend) | Not started | Empty placeholder files only |
| Nginx (SSL termination, reverse proxy) | Not started | Config is empty placeholder |
| Honeypots not internet-facing | Blocking for real data | All current attacker traffic is synthetic Kali injection |
| No unit / integration test suite | Quality gap | Only ad-hoc CLI smoke tests exist (`--single-ip`, `--profile-only`) |
| `profiler.py` uncommitted | Workflow gap | Should be committed to `zeineb` branch with a descriptive message |

### 11.3 · Recommended next steps (ordered)

1. Commit `profiler.py` + `engine.py` + `schema.sql` changes on branch `zeineb`.
2. Delete dead modules (`mitre_llm.py`, `ollama_mitre.py`, `virustotal_scanner.py`) and consolidate YARA directories.
3. Move `PROFILER_*.md` into `docs/`.
4. Fix the `elasticsearch-py` deprecation by switching to `.options(ignore_status=404)`.
5. Harden `verify_coc.py` into a CI check (exit code already correct; wire into GitHub Actions).
6. Plan Sprint 4 — FastAPI routes that surface `forensic_sessions`, `suspect_profiles`, and `forensic_iocs` to the frontend.
7. Move honeypots behind a public IP (or Cloudflare Tunnel) to start collecting real attacker data; re-run `engine.py --hours 168` weekly.

---

**Audit author:** Claude Code (Opus 4.7)
**Files read in full:** 22 Python modules + schema.sql + 10 YARA files + Dockerfile + requirements.txt
**Verification:** all row counts, container uptimes, and index statistics taken from live queries against `forenhive-postgresql`, `forenhive-elasticsearch`, and `forenhive-ollama` at audit time.
**Document status:** ready for inclusion as Chapter 4 of the PFE report.
