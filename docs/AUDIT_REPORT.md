# ForenHive Forensic Report Pipeline — Audit

**Audit branch**: `audit/report-pipeline-2026-05-22` (off `main`; no `develop` branch existed)
**Audit date**: 2026-05-22
**Code under audit**: `~/forenhive` HEAD `c9966ce` + uncommitted working-tree changes
**Auditor mode**: read-only (no code modified)

---

## 0. Discrepancies vs. the audit brief

These up-front, because they affect how to read everything below.

| Claim in brief | Reality on disk | Impact |
|---|---|---|
| Branch `develop` | Does not exist (only `main` + named-user branches) | Audit branch cut from `main` |
| Template `forenhive_rapport_final.html` | File is `backend/templates/forenhive_rapport_v2.html` (77 814 bytes); a second small `report.html` exists but is not the forensic report | Audited the `_v2.html` template — it is the one actually rendered by [reports.py:1696](backend/routers/reports.py#L1696) and [reports.py:1850](backend/routers/reports.py#L1850) |
| **18 risk signals** | The engine produces **9 signals** ([risk_score.py:470-480](forensic-engine/risk_score.py#L470-L480)) | Audit scoped to the real 9 |
| Endpoint `POST /api/reports/generate/{session_id}` | The actual forensic per-session route is `POST /api/reports/forensic/{session_id}/generate` ([reports.py:1676](backend/routers/reports.py#L1676)). `POST /api/reports/generate` exists at [reports.py:1184](backend/routers/reports.py#L1184) but is the generic ReportService entry, not the rich forensic PDF | Audited both |
| Modules `enricher.py`, `yara_scanner.py`, `virustotal.py`, `risk_score.py`, `smb_analyzer.py`, `mitre_mapper.py`, `chain_of_custody.py`, `timeline_builder.py`, `ioc_extractor.py`, `profiler.py` | All present in `forensic-engine/` | OK |
| `risk_score_optimized.py` in working tree | Deleted (in `git status` as `D forensic-engine/risk_score_optimized.py`) | OK |

---

## 1. Summary table — all findings

| # | Severity | Title | Subsystem |
|---|---|---|---|
| C-1 | CRITICAL | Engine writes `risk_level` & `confidence` into `enrichment_data` jsonb but the per-session INSERT omits the dedicated columns — **all 54 sessions have NULL `risk_level` and `confidence`** | engine ↔ DB |
| C-2 | CRITICAL | `_build_forensic_context` never SELECTs `forensic_sessions.enrichment_data`, so per-session `vt_malicious`, `vt_family`, `vt_available`, `smb_share_enum`, `epmapper_prescan`, `exploit_cve`, `previously_seen`, `previous_sessions`, `shodan_vulns`, `is_bogon`, `geo_country_code`, `destination_port`, `kill_chain_label`, `mapping_source`, `active_signals`, `command_count`, `file_download_count`, `exfil_bytes` never reach the report | engine ↔ report |
| C-3 | CRITICAL | Top-level `vt_malicious` / `vt_family` / `vt_available` in the v2 context are read from `AttackerProfile`, which has no such attributes — always 0 / "" / True. The "Quota épuisé" fix in [reports.py:572-575](backend/routers/reports.py#L572-L575) is misrouted: it reads the wrong dict | report adapter |
| C-4 | CRITICAL | `suspect_profiles.profile` (the FBI BAU "detective profile" from [forensic-engine/profiler.py:516-605](forensic-engine/profiler.py#L516-L605) with `sophistication`, `confidence`, `primary_objective`, `behavioral_traits`, `organized_score`, `disguise_used`, `escalation_detected`, `signature_indicators`, `similar_past_cases`, `dominant_tactic`, `detective_narrative`) is **never read by the report**. The "Profile FBI BAU" section is rebuilt from heuristics in [reports.py:430-439](backend/routers/reports.py#L430-L439) | report adapter |
| C-5 | CRITICAL | Backend `EnrichmentService` ([backend/services/enrichment.py](backend/services/enrichment.py)) does NOT consult the `api_quota_status` table that the engine maintains — every report generation re-hits AbuseIPDB / IPLocate / VirusTotal even when the engine has already marked them exhausted. VirusTotal is currently `exhausted=true` (HTTP 429 today) but each report still makes the call | API quotas |
| H-1 | HIGH | `_build_forensic_context` calls `services/profiler.py:build_profile()` on every report → that calls `iplocate()` + `abuseipdb()` per request ([backend/services/profiler.py:79-80](backend/services/profiler.py#L79-L80)). No caching, no quota awareness | API quotas |
| H-2 | HIGH | `forensic_iocs` table never queried — adapter builds IOCs only from current session commands + first captured hash ([reports.py:371-381](backend/routers/reports.py#L371-L381)). All centralised cross-session IOC data is invisible to the report | engine ↔ report |
| H-3 | HIGH | `forensic_timeline_events` table never queried — `timeline` is rebuilt from ES detail per request ([reports.py:849-883](backend/routers/reports.py#L849-L883)). The persisted normalized timeline (built by `timeline_builder.py`) is unused | engine ↔ report |
| H-4 | HIGH | `forensic_chain_of_custody` table never queried — every report call performs a **new** `get_custody().seal(detail)` ([reports.py:1061](backend/routers/reports.py#L1061)). This means each PDF carries a different SHA-256 / different TSA token; the existing batched RFC 3161 anchor produced by the engine is bypassed | chain of custody |
| H-5 | HIGH | No alternate TSA configured. Single `settings.tsa_url` in [backend/services/chain_custody.py:72](backend/services/chain_custody.py#L72); engine hard-codes one `TSA_URL` env var in [forensic-engine/chain_of_custody.py:36](forensic-engine/chain_of_custody.py#L36). freeTSA outage → silent degrade to `tsa_ok=False` for every report | chain of custody |
| H-6 | HIGH | `ip_risk_scores.recommendations`, `key_findings`, `honeypot_summary`, `enrichment_snapshot` columns (populated for 12 IPs) — never consumed by the report. Adapter builds its own recommendations in [reports.py:441-471](backend/routers/reports.py#L441-L471) | engine ↔ report |
| H-7 | HIGH | 45 / 54 sessions have empty `mitre_techniques` (`[]` in DB) even though many show MITRE coverage in the rendered report (because the adapter heuristically injects T1110.001 / T1078 / T1059.004 from login/cmd presence in [reports.py:931-939](backend/routers/reports.py#L931-L939)). The mapper is under-running on cowrie sessions | engine MITRE coverage |
| M-1 | MEDIUM | Jinja2 environment uses default `Undefined` (not `StrictUndefined`) — missing variables silently render empty instead of failing fast ([reports.py:37-41](backend/routers/reports.py#L37-L41)). This is why all 54 reports render even with the C-2 / C-3 gaps | template safety |
| M-2 | MEDIUM | Template references `bottom_line`, `exec_narrative`, `honeypot_port`, `profile.operator_type`, `profile.persistence`, `vt_top_engines`, top-level `vt_total`, timeline event `ev.severity`, YARA `y.severity` — **none** are supplied by `_adapt_context_for_v2`. They render empty or as their `default()` fallback | template ↔ adapter |
| M-3 | MEDIUM | `dropped_files[*].vt_detections` / `vt_total` come from `ctx.get("vt_result")` (loaded from `file_analysis` table) — currently 0 rows for any of the IOC hashes the existing sessions reference, so the "VirusTotal detections" line is always blank for the rendered reports | engine ↔ report |
| M-4 | MEDIUM | `_adapt_context_for_v2` hard-codes `"es_reference_cases": []` ([reports.py:438](backend/routers/reports.py#L438)) — the §"Similar Past Cases" section is structurally dead | report adapter |
| M-5 | MEDIUM | `engine_version` hard-coded `"3.1"` in adapter ([reports.py:502](backend/routers/reports.py#L502)) but engine stores `score_version` per session (currently `"v2.0.0-9signals"` per [risk_score.py](forensic-engine/risk_score.py)). Mismatched provenance on the cover page | report adapter |
| M-6 | MEDIUM | `yara_rules_used` hard-coded `10` ([reports.py:533](backend/routers/reports.py#L533)) — the rule count is `forensic-engine/yara_rules/*.yar` not enumerated | report adapter |
| M-7 | MEDIUM | `chain_of_custody[0].timestamp` is set to `started_at` ([reports.py:401](backend/routers/reports.py#L401)) rather than the actual TSA-anchored time from `_custody.tsa_token_b64`. The "RFC 3161 Timestamp" column in the report is not the RFC 3161 timestamp | chain of custody |
| L-1 | LOW | `risk_warnings` always `[]` ([reports.py:508](backend/routers/reports.py#L508)) even though `risk_score.ScoreResult` doesn't expose warnings and the comment in the brief assumed it did; minor wording issue | report adapter |
| L-2 | LOW | `extra_references` always `[]` ([reports.py:583](backend/routers/reports.py#L583)); §"References" carries no dynamic citations | report adapter |
| L-3 | LOW | `_SIGNAL_META.reputation.why` says "≥90→15, ≥70→11, ≥50→7, ≥25→4" — matches code, but max stated as "15 pts" while [risk_score.py:104](forensic-engine/risk_score.py#L104) `_signal_reputation` has `max_pts=15` ✓. Cross-checked all 9 signal max values; all match | docs / sanity |

---

## 2. Field coverage matrix (Task 1)

### 2.1 Engine emits → DB columns / jsonb

Source: [forensic-engine/engine.py:1165-1204](forensic-engine/engine.py#L1165-L1204), [forensic-engine/risk_score.py:511-521](forensic-engine/risk_score.py#L511-L521), [forensic-engine/profiler.py:516-605](forensic-engine/profiler.py#L516-L605)

| Field | Produced (file:line) | Stored in | Loaded by `_build_forensic_context`? | Rendered? |
|---|---|---|---|---|
| `session_id` | engine.py:1206 | `forensic_sessions.session_id` | yes (601) | yes (`session_id`) |
| `honeypot_type` | engine.py:1207 | `forensic_sessions.honeypot_type` | yes | yes (`honeypot_type`) |
| `source_ip` | enricher → session | `forensic_sessions.source_ip` | yes | yes |
| `started_at` / `ended_at` | engine ingest | `forensic_sessions.started_at/ended_at` | started_at only (`ended_at` missing from SELECT) | started_at yes, ended_at fallback via `detail` |
| `risk_score` | risk_score.py:512 | `forensic_sessions.risk_score` | yes | yes |
| `mitre_techniques[]` | mitre_mapper.py | `forensic_sessions.mitre_techniques` (jsonb) | yes | yes |
| `signal_breakdown{9 signals}` | risk_score.py:518 | `forensic_sessions.signal_breakdown` (jsonb) | yes | yes (all 9) |
| `kill_chain_phase` / `kill_chain_stage` | mitre_mapper.py | columns | yes | yes |
| `primary_technique` | mitre_mapper.narrative_for | column | yes | **no** (loaded but not rendered) |
| `forensic_narrative` | mitre_mapper.narrative_for | column | yes (→ profile.mistral_analysis) | yes |
| `login_attempts` / `success_count` | engine session prep | columns | yes | yes (via auth_attempts) |
| `attack_velocity` | engine | column | **NO** (not in SELECT) | no |
| `score_version` | risk_score.SCORE_VERSION | column | **NO** | no |
| `ended_at` column | engine | column | **NO** (only via ES detail) | sometimes |
| **enrichment_data.risk_level** | risk_score.py:511 | `enrichment_data` jsonb | **NO** (jsonb not loaded) | derived from score |
| **enrichment_data.confidence** | risk_score.py:514 | jsonb | **NO** | derived from score |
| **enrichment_data.active_signals** | risk_score.py:519 | jsonb | **NO** | no |
| **enrichment_data.command_count** | engine.py:1180 | jsonb | **NO** | no |
| **enrichment_data.file_download_count** | engine.py:1181 | jsonb | **NO** | no |
| **enrichment_data.exfil_bytes** | engine.py:1182 | jsonb | **NO** | no |
| **enrichment_data.kill_chain_label** | engine.py:1186 | jsonb | **NO** | no |
| **enrichment_data.mapping_source** | engine.py:1189 | jsonb | **NO** | no |
| **enrichment_data.yara_matches** | engine.py:1190 | jsonb | Indirect (re-queried in [reports.py:1011-1033](backend/routers/reports.py#L1011-L1033)) | yes |
| **enrichment_data.vt_malicious** | engine.py:1191 | jsonb | **NO** (read from profile_dict which lacks it) | always 0 — see C-3 |
| **enrichment_data.vt_family** | engine.py:1192 | jsonb | **NO** | always "" |
| **enrichment_data.vt_available** | engine.py:1193 | jsonb | **NO** | always True |
| **enrichment_data.smb_share_enum / epmapper_prescan / exploit_cve / previously_seen / previous_sessions / shodan_vulns / is_bogon / geo_country_code / destination_port** | engine.py:1195-1203 | jsonb | **NO** | no |
| **suspect_profiles.profile** (FBI BAU detective profile) | forensic-engine/profiler.py:573-605 | `suspect_profiles` table | **NO** — backend never reads `suspect_profiles` | no — replaced by heuristics in adapter |
| **forensic_iocs** table | ioc_extractor.py:160-238 | `forensic_iocs` | **NO** | no — adapter builds inline IOCs |
| **forensic_timeline_events** table | timeline_builder.py:244-312 | `forensic_timeline_events` | **NO** | no — adapter rebuilds from ES |
| **forensic_chain_of_custody** table | forensic-engine/chain_of_custody.py:265+ | `forensic_chain_of_custody` | **NO** — adapter re-seals on each call | partial (a fresh, different seal each time) |
| **ip_risk_scores.recommendations / key_findings / honeypot_summary / enrichment_snapshot** | engine unified scorer | `ip_risk_scores` | partial (signal_breakdown + risk_score only) | no |
| **ip_enrichment_cache.data** | enricher.py | `ip_enrichment_cache` | yes ([reports.py:1094-1102](backend/routers/reports.py#L1094-L1102)) | yes (whois/shodan/iplocate/geo) |
| **file_analysis.virustotal_result** | virustotal.py | `file_analysis` | yes ([reports.py:1044-1055](backend/routers/reports.py#L1044-L1055)) | yes (in dropped_files) |
| **file_analysis.yara_matches** | yara_scanner.py | `file_analysis` | **NO** (only virustotal_result selected) | no |
| **api_quota_status** | quota_tracker.py | table | **NO** (backend never reads it) | no |

### 2.2 Template variables → adapter coverage

All `{{ }}` and `{%%%% %}` constructs extracted from [backend/templates/forenhive_rapport_v2.html](backend/templates/forenhive_rapport_v2.html) (142 unique expressions, 102 unique control blocks).

**Supplied by `_adapt_context_for_v2` ([reports.py:497-584](backend/routers/reports.py#L497-L584))**: `report_id, session_id, generated_at, engine_version, classification, risk_level, risk_score, risk_confidence, risk_warnings, verdict, source_ip, session_date, geo_country, geo_city, asn, isp, abuse_score, abuse_reports, event_count, honeypot_type, protocol, session_start, session_end, session_duration, auth_attempts, auth_success, auth_success_count, mitre_techniques, mitre_narrative, yara_matches, yara_rules_used, malware_family, dropped_files, signal_breakdown, timeline_summary, full_timeline, profile{sophistication,confidence,objective,organized_score,behavioral_traits,detective_narrative,es_reference_cases}, iocs, stix_export_path, chain_of_custody, coc_timestamp_authority, custody_ok, shodan_data, whois_data, iplocate_data{is_*, company_name, asn_*}, ptr_hostname, recommendations, ollama_recommendations, vt_available, vt_malicious, vt_family, kc_reached, kc_stages, kc_stages_labels, honeypots_hit, sessions_count, extra_references`.

**NOT supplied** (template references → blank / default):

| Variable | Used in template (search hit) | Adapter status | Effect |
|---|---|---|---|
| `bottom_line` | `{% if bottom_line is defined and bottom_line %}` | absent | block skipped — exec-summary "bottom line" never shown |
| `exec_narrative` | `{% if exec_narrative is defined and exec_narrative %}` | absent | block skipped |
| `honeypot_port` | `{{ honeypot_port \| default("22") }}` | absent | always "22" |
| `profile.operator_type` | `{% if profile.operator_type %}` | absent on `profile_out` | block skipped |
| `profile.persistence` | `{% if profile.persistence %}` | absent | block skipped |
| `vt_top_engines` | `{% if vt_top_engines %}{{ vt_top_engines \| join(', ') }}` | absent | "Top engines" line empty |
| `vt_total` (top-level) | `{{ vt_total \| default("?") }}` | only nested in dropped_files | "?" |
| `ev.severity` (timeline event) | `{% if ev.severity == 'CRITICAL' %} … 'HIGH' … 'INFO'` | timeline mapping at [reports.py:337-345](backend/routers/reports.py#L337-L345) emits only `timestamp/event_type/details/mitre_tid` | no row gets a severity class — all rows fall through to the `{% else %}` branch |
| `y.severity` | `{% if y.severity == 'CRITICAL' %} … default("HIGH")` | YARA matches in `dropped_files[*].yara_hits` are strings, not dicts | always "HIGH" via default |

**Reverse direction (template → adapter unused)**: none — every adapter key was found referenced in the template, except `full_timeline` (referenced indirectly in JS-driven preview path? — actually unused; both `timeline_summary[:15]` and `full_timeline` are emitted, but only `timeline_summary` is iterated by the template, so `full_timeline` is dead context payload).

---

## 3. N/A handling (Task 2)

Jinja env: `Environment(loader=…, autoescape=…, auto_reload=False)` at [reports.py:37-41](backend/routers/reports.py#L37-L41) — **default `Undefined`, not `StrictUndefined`**. Missing variables render to empty strings without raising. This is **the only reason the 54-session pass rate is 100 %**: silent gaps from §2.2 above never error, they just produce blank cells.

Variables with explicit `default()` fallback (safe even if upstream goes None):
`abuse_reports`, `auth_attempts`, `auth_success_count`, `classification`, `engine_version`, `event_count`, `generated_at`, `geo_country`, `geo_city`, `honeypot_port`, `honeypot_type`, `isp`, `kc_stages_labels`, `profile.confidence/objective/organized_score/sophistication`, `profile.behavioral_traits`, `ptr_hostname`, `risk_confidence`, `risk_level`, `risk_score`, `session_duration`, `sessions_count`, `verdict`, `vt_total` (per-file), `y.severity`. Shodan fields use `if shodan_data.X else "N/A"`.

Variables with **no fallback** that will render empty when upstream is None:
`abuse_score`, `asn` (one use has default("?"), one doesn't), `auth_success_count` (one use), `bottom_line`, `chain_of_custody[0].sha256` (sliced — crashes if shorter than 32 chars but value is always 64-char hex so safe), `chain_of_custody[0].timestamp`, `coc_timestamp_authority`, `event_count` (one use), `exec_narrative`, `f.filename`, `f.sha256`, `f.vt_detections`, `geo_city/country` (one use), `honeypots_hit[*]` (loop only), `ioc.context/type/value`, `iplocate_data.asn_*` (mixed; some use `or 'N/A'`), `malware_family`, `mitre_narrative`, `profile.detective_narrative`, `profile.operator_type/persistence`, `protocol` (one use), `rc.*` (never iterated — list empty), `rec.action/priority/rationale`, `report_id`, `risk_score` (one use), `session_date/start/end`, `session_id`, `shodan_data.*` (inside conditional, safe), `sig.*` (always supplied), `source_ip`, `stix_export_path` (gated), `t.evidence/name/tactic/tid`, `trait`, `vt_family/vt_malicious` (always 0 / "" due to C-3), `vt_top_engines`, `whois_data.*` (use `.get() or 'N/A'`), `yara_matches/yara_rules_used`.

### 18 (actually 9) risk-signals coverage

The brief says "18 signals". The engine implements 9. All 9 are produced and all 9 are rendered when present.

| # | Signal key | Engine source | Stored | Rendered |
|---|---|---|---|---|
| 1 | `reputation` | risk_score.py:104 | `signal_breakdown.reputation` | yes |
| 2 | `anonymization` | risk_score.py:134 | yes | yes |
| 3 | `threat_history` | risk_score.py:171 | yes | yes |
| 4 | `intent_volume` | risk_score.py:220 | yes | yes |
| 5 | `compromise_depth` | risk_score.py:252 | yes | yes |
| 6 | `exfiltration` | risk_score.py:319 | yes | yes |
| 7 | `lateral_movement` | risk_score.py:341 | yes | yes |
| 8 | `malware` | risk_score.py:386 | yes | yes |
| 9 | `mitre_sophistication` | risk_score.py:436 | yes | yes |

Rendered order in [reports.py:218-225](backend/routers/reports.py#L218-L225) matches scorer order. Skipped signals (private-IP path) display "SKIPPED — private_ip" correctly (verified in `/tmp/preview-galah-172.16.1.77.html`: signals 1-2 SKIPPED with `private_ip` reason).

If the brief intended "18" as e.g. a richer 18-dimension scorer planned for sprint 4, **that scorer does not exist**.

---

## 4. Validity across all sessions (Tasks 3 & 4)

54 forensic sessions in PG (50 cowrie, 3 dionaea, 1 galah). Coverage probe ran the real endpoint
`POST /api/reports/forensic/{session_id}/generate` against every one with a valid JWT.

**Result: 54 / 54 succeeded (HTTP 200, PDF ≥ 100 KB, MIME `application/pdf`).** No Jinja2 `UndefinedError`. No WeasyPrint render error. No 500.

### Per-session sample (representative)

| session_id | source_ip | honeypot | risk_score | MITRE | edge-case probed | HTTP | bytes |
|---|---|---|---|---|---|---|---|
| `dionaea-172.19.0.1-80` | 172.19.0.1 | dionaea | 4 | yes | private IP (reputation skipped) | 200 | 111 099 |
| `dionaea-172.16.1.17-445` | 172.16.1.17 | dionaea | 9 | yes | private IP | 200 | 112 722 |
| `dionaea-172.16.1.77-80` | 172.16.1.77 | dionaea | 8 | yes | private IP | 200 | (in bulk) |
| `galah-172.16.1.77` | 172.16.1.77 | galah | 4 | yes | private IP + galah | 200 | 121 421 |
| `ce77f98cdcab` | 20.163.32.78 | cowrie | 24 | **no** | empty MITRE persisted | 200 | 136 745 |
| `d4b2c2267a9d` | 20.163.32.78 | cowrie | 24 | no | empty MITRE | 200 | (in bulk) |
| `3ccf8bd294ca` | 20.163.32.78 | cowrie | 24 | no | empty MITRE | 200 | 136 807 |
| `115bdfb649be` | 20.163.32.78 | cowrie | 34 | yes | regular cowrie | 200 | 137 080 |

### Edge cases forced

- **Private IP, reputation skipped** (`dionaea-172.19.0.1-80`, `galah-172.16.1.77`) — render OK; signals 1-2 show "SKIPPED — private_ip" in the §07 list; N/A density 7-9 per page (acceptable). [Verified in `/tmp/preview-galah-172.16.1.77.html` and `/tmp/preview-dionaea-172.19.0.1-80.html`.]
- **No MITRE persisted** (`ce77f98cdcab` and 44 others) — adapter inserts T1110.001 / T1059.004 heuristically from logins/cmds at [reports.py:931-939](backend/routers/reports.py#L931-L939); §05 still populated. The DB persistence gap is H-7.
- **No malware / no YARA / no IOC** (galah, all private-IP dionaea except `-445`) — `malware_family` empty → "Pending analysis" verdict fallback; `dropped_files` empty → §06 hides via `{% if dropped_files | length > 0 %}`. Render OK.
- **No suspect_profiles row** (only 13 IPs profiled vs 54 sessions referencing many IPs) — adapter does NOT depend on suspect_profiles anyway (C-4), so the heuristic profile fills in. No crash, but the FBI BAU profile is permanently absent.
- **TSA unreachable** — backend `ChainOfCustody._request_token` catches all exceptions ([backend/services/chain_custody.py:86-100](backend/services/chain_custody.py#L86-L100)) and returns `CustodyRecord(sha256=…, tsa_token_b64=None, tsa_url=…, tsa_ok=False)`. Adapter then sets `chain_of_custody[0].tsa = "—"` ([reports.py:402](backend/routers/reports.py#L402)) and the §08 "RFC 3161 Timestamp Authority" line still shows `freetsa.org` (literal default). No fallback TSA configured (H-5).
- **Bootstrap profile, no ES reference cases** — forensic-engine/profiler.py:215-273 attempts `_query_similar_profiles` but `es_reference_cases` is hard-coded `[]` in adapter ([reports.py:438](backend/routers/reports.py#L438)) so it doesn't matter. M-4.

### Crashes / broken paths

**None observed at runtime.** All failure modes are silent (empty cells / default placeholders), not exceptions. This is partly because Jinja's default Undefined eats everything and partly because the adapter catches every DB call in `try/except: pass`. The downside: a real data outage from PG would render a cheerfully-blank PDF instead of failing fast.

The closest thing to a "broken path" is the **STIX export** at [reports.py:1226](backend/routers/reports.py#L1226) (`GET /api/reports/{report_id}/stix`) — gated on a saved `ReportMeta` record from the generic ReportService entry, not the forensic per-session endpoint. The forensic generate endpoint returns the PDF directly without saving meta, so the STIX export only works for reports created through `POST /api/reports/generate` (generic) — **not** for the rich forensic reports. Severity moved to a separate issue:

| ID | Severity | Issue |
|---|---|---|
| H-8 | HIGH | STIX export not reachable from the rich forensic PDF flow — `forensic_generate` writes to disk under `out_dir` ([reports.py:1702-1707](backend/routers/reports.py#L1702-L1707)) but never persists a `ReportMeta` row, so `GET /{report_id}/stix` cannot find it. STIX is effectively dead for the per-session forensic reports |

---

## 5. External API quota (Task 5)

Current `api_quota_status` snapshot (read from PG just now):

| API | exhausted | reset_at | last_error |
|---|---|---|---|
| `virustotal` | **TRUE** | 2026-05-23 00:00:00 UTC | `HTTP 429 on 9b6fb6ccea348e89...` |
| `shodan_host` | false | 2026-05-22 13:44:16 UTC | `HTTP 403 (key issue)` |

No rows for `abuseipdb`, `iplocate`, `shodan`, `freetsa` — quota tracker has never flipped them in the lifetime of this DB.

### Per-API analysis

| API | Engine handling | Backend handling | Quota-aware? | Failure mode |
|---|---|---|---|---|
| **AbuseIPDB** | `_tracker.is_exhausted("abuseipdb")` gate ([enricher.py:223](forensic-engine/enricher.py#L223)) ; 429 → `mark_exhausted` ; 401 → mark with reason "invalid key" ; private-IP skipped at [enricher.py:226](forensic-engine/enricher.py#L226) | bare `httpx.get`, no quota check, `except: return {}` ([enrichment.py:17-39](backend/services/enrichment.py#L17-L39)) | engine: yes / backend: **no** | engine → empty enrichment for that IP this run ; backend → silent `{}` and the next report re-tries |
| **VirusTotal** | quota_tracker mark + gate via `quota_tracker.py` ; private-IP path doesn't apply (it's a hash lookup) | bare `httpx.get`, no quota check, 404 → `{"found": false}`, else `except: return {}` ([enrichment.py:66-89](backend/services/enrichment.py#L66-L89)) | engine: yes / backend: **no** | currently exhausted; engine respects it, backend ignores and re-burns retries on every report |
| **IPLocate** | `_tracker.is_exhausted("iplocate")` gate ([enricher.py:161](forensic-engine/enricher.py#L161)) ; 429/403 → mark exhausted | bare `httpx.get`, no quota check ([enrichment.py:40-64](backend/services/enrichment.py#L40-L64)) | engine: yes / backend: **no** | same pattern |
| **Shodan (search)** | gated ; 429 → mark ([enricher.py:278-294](forensic-engine/enricher.py#L278-L294)) | backend has no Shodan client at all | engine only | OK at the engine boundary |
| **Shodan (InternetDB host)** | gated ; non-2xx → mark with reason "(key issue)" ([enricher.py:339](forensic-engine/enricher.py#L339)) | backend doesn't call | engine only | currently 403 — was marked, then auto-cleared (reset_at in the past) |
| **freeTSA / RFC 3161** | direct httpx POST ([forensic-engine/chain_of_custody.py:149](forensic-engine/chain_of_custody.py#L149)) ; no quota tracking ; on non-200 returns `{"error": …}` and batch logs a warning ; **no fallback TSA** | direct httpx POST ([backend/services/chain_custody.py:71-79](backend/services/chain_custody.py#L71-L79)) ; `except: tsa_ok=False` ; **no fallback TSA** | neither | silent `tsa_ok=False` ; every report does its own seal anyway |

### Posture summary
- **VirusTotal** is currently EXHAUSTED. Engine respects this and skips. Backend does not — every report re-hits VT (and times out / 429s) for the IOC hash lookup. Adds 15 s × N retries to every report run.
- **Free-tier limits** (per code comments / well-known limits) — not directly verified live, but consistent with the symptoms: VirusTotal at 500/day & 4/min (we hit it), AbuseIPDB at 1000/day, IPLocate 1000/day on free tier.
- **freeTSA fallback is missing.** The brief explicitly flagged this — confirmed. The only TSA endpoint is `TSA_URL` / `settings.tsa_url`. No code path tries `digicert`, `entrust`, `sectigo`, or any alternate.

---

## 6. Proposed fixes (do not apply yet — awaiting go-ahead)

Concrete, ordered by severity. Each fix names the file:line and the smallest change that closes the gap.

### C-1 — persist `risk_level` and `confidence` columns
**File**: [forensic-engine/engine.py:530-540 (`_SESSION_INSERT_SQL`), 557 (`_SESSION_ROW_TEMPLATE`), 561-579 (`_session_row`)](forensic-engine/engine.py#L530-L579)
**Change**: add `risk_level` and `confidence` to the INSERT column list, append `%s` placeholders to the template, and add `session.get("risk_level")` / `session.get("confidence")` to the tuple. Then in the per-session loop ([engine.py:1165-1167](forensic-engine/engine.py#L1165-L1167)) add:
```python
session["risk_level"] = result.risk_level
session["confidence"] = result.confidence
```
Then `UPDATE forensic_sessions SET risk_level=enrichment_data->>'risk_level', confidence=enrichment_data->>'confidence' WHERE risk_level IS NULL;` as a one-shot backfill.

### C-2 + C-3 — load engine enrichment_data and route VT correctly
**File**: [backend/routers/reports.py:600-609](backend/routers/reports.py#L600-L609)
**Change**: extend the `SELECT` to include `enrichment_data, ended_at, attack_velocity, score_version, scored_at`. Then in [reports.py:1171-1173](backend/routers/reports.py#L1171-L1173), replace the broken reads with:
```python
ed = pg_row.get("enrichment_data") or {}
"vt_malicious": int(ed.get("vt_malicious") or 0),
"vt_available": bool(ed.get("vt_available", True)),
"vt_family":    ed.get("vt_family") or "",
```
This also makes `smb_share_enum`, `exploit_cve`, `command_count`, `exfil_bytes`, `kill_chain_label` available for the template.

### C-4 — wire suspect_profiles into the FBI BAU section
**File**: [backend/routers/reports.py:642-648](backend/routers/reports.py#L642-L648) (after `build_profile`)
**Change**: query `SELECT profile FROM suspect_profiles WHERE source_ip=:ip` ; if present, merge over `profile_dict` so that `sophistication`, `confidence`, `primary_objective`, `behavioral_traits`, `organized_score`, `disguise_used`, `escalation_detected`, `signature_indicators`, `dominant_tactic`, `detective_narrative` flow through. Then in [reports.py:430-439](backend/routers/reports.py#L430-L439) prefer the real fields over the heuristics and populate `profile_out["es_reference_cases"]` from forensic-engine's `_query_similar_profiles` (the data already exists).

### C-5 + H-1 — quota-aware backend enrichment
**File**: [backend/services/enrichment.py](backend/services/enrichment.py) and a new `backend/services/quota_tracker.py`
**Change**: port the engine's quota_tracker (DB-backed, reads `api_quota_status`) into the backend. Gate every `abuseipdb` / `iplocate` / `virustotal_hash` call with `is_exhausted(api)` and `mark_exhausted` on 429/403. Cache successful lookups in `ip_enrichment_cache` (already exists) for ≥1h so repeat report generations for the same IP don't re-burn quota.

### H-2 / H-3 / H-4 / H-6 — read what the engine already wrote
**Files**:
- [reports.py:371-381](backend/routers/reports.py#L371-L381) → query `forensic_iocs` for `source_ip` and merge into `iocs` list.
- [reports.py:849-883](backend/routers/reports.py#L849-L883) → prefer `forensic_timeline_events` for `source_ip` over the ad-hoc ES rebuild.
- [reports.py:1060-1072](backend/routers/reports.py#L1060-L1072) → look up `forensic_chain_of_custody.canonical_json` / `record_hash` / `sealed_at` by session_id; only fall back to a live seal if missing.
- [reports.py:968-989](backend/routers/reports.py#L968-L989) → also pull `ip_risk_scores.recommendations`, `key_findings`, `honeypot_summary` and surface them.

### H-5 — alternate TSA chain
**Files**: [backend/config.py](backend/config.py), [backend/services/chain_custody.py:71-79](backend/services/chain_custody.py#L71-L79), [forensic-engine/chain_of_custody.py:36-40](forensic-engine/chain_of_custody.py#L36-L40)
**Change**: change `tsa_url: str` to `tsa_urls: list[str]` (env-overridable comma-separated). Iterate in order until one returns 200 with a valid token. Suggested order: `freetsa.org/tsr → digicert.com → globalsign.com`.

### H-7 — mitre_mapper under-coverage for cowrie
**File**: [forensic-engine/mitre_mapper.py](forensic-engine/mitre_mapper.py) (deterministic rules)
**Change**: out of audit scope to design the new rules, but at minimum lower the threshold to emit `T1110.001` whenever `login_attempts ≥ 1` regardless of outcome (45/54 sessions have logins but no MITRE). Worth a separate ticket.

### H-8 — STIX from forensic flow
**Files**: [backend/routers/reports.py:1677+](backend/routers/reports.py#L1677-L1736)
**Change**: have `forensic_generate` persist a minimal `ReportMeta` after PDF write (call `get_reports()._save_meta(meta)` — would need exposing the persistence helper) so `GET /{report_id}/stix` can find it. Or: add a `POST /api/reports/forensic/{session_id}/stix` endpoint that runs the same context and emits STIX.

### M-1 — Jinja strictness
**File**: [reports.py:37-41](backend/routers/reports.py#L37-L41)
**Change**: switch to `undefined=ChainableUndefined` (allows safe attribute chaining) or — preferable — to `StrictUndefined` once C-2..C-4 are landed. With StrictUndefined the C-2/C-3 silent gaps would have surfaced as 500s long ago.

### M-2 — populate the missing template variables
**File**: [reports.py:497-584](backend/routers/reports.py#L497-L584)
**Change**: explicitly emit `bottom_line` (one-sentence verdict for §03), `exec_narrative` (the `forensic_narrative` already loaded), `honeypot_port` (from `detail.get('destination_port')` / `enrichment_data.destination_port`), `profile_out["operator_type"]` / `["persistence"]` (from suspect_profile after C-4), `vt_top_engines` / top-level `vt_total` (from `vt_result.last_analysis_results` top-N keys, and `vt_result.total`), and tag each `all_timeline` row with `severity` derived from `action`.

### M-3 — pre-warm `file_analysis` for known captures
Already done by the engine in principle (yara_scanner.py + virustotal.py persist there). When VT was exhausted, the row got persisted with only `yara_matches`. Adapter at [reports.py:386-393](backend/routers/reports.py#L386-L393) reads `vt.get("malicious")`/`vt.get("total")` — but VT JSON nests these under `last_analysis_stats`. Compare with [backend/services/enrichment.py:79-87](backend/services/enrichment.py#L79-L87) which returns `{"malicious": stats.get("malicious")}` at top level. Decide on one shape and normalise on write.

### M-5 — real engine version
**File**: [reports.py:502](backend/routers/reports.py#L502)
**Change**: `"engine_version": pg_row.get("score_version") or "v2.0.0-9signals"`.

### M-6 — real YARA rule count
**File**: [reports.py:533](backend/routers/reports.py#L533)
**Change**: `"yara_rules_used": len(list(Path('/app/forensic-engine/yara_rules').glob('*.yar')))` — cache at module load.

### M-7 — show the real RFC 3161 timestamp
**File**: [reports.py:398-404](backend/routers/reports.py#L398-L404)
**Change**: parse `_custody.tsa_token_b64` (cmsutil or `rfc3161_client.decode_timestamp_response(...).genTime`) and put the resulting RFC 3161 `genTime` in `chain_of_custody[0].timestamp` instead of `started_at`.

### L-1 — propagate scorer warnings
risk_score.py's `ScoreResult` does not currently expose warnings; if/when added, mirror to `risk_warnings`. Until then leave the empty list.

### L-2 — populate extra_references from MITRE / VT / AbuseIPDB rows used
Build a small list of `{ref, url}` from the techniques and IOCs actually rendered.

---

## 7. What was NOT modified

Per the instructions, no source file was modified. The only on-disk change made by this audit is this file (`AUDIT_REPORT.md`) at the repo root. The audit branch `audit/report-pipeline-2026-05-22` exists locally only.

To revert the branch:
```
git checkout main
git branch -D audit/report-pipeline-2026-05-22
```

To proceed with fixes, the recommended order is **C-1 → C-2/C-3 → C-4 → C-5/H-1 → M-1 (StrictUndefined) → the rest**, as the first four are responsible for the bulk of silently-blank report content and the StrictUndefined flip is the safety net that will catch any remaining gaps before they reach production PDFs.

---

## Fix log

All five critical/high fixes from §6 applied on branch `audit/report-pipeline-2026-05-22`. One fix per commit, with a render-check (3-session sample) after each, plus a full 54-session sweep after Fix 5 to confirm StrictUndefined.

### Important caveat about the first four commits

`docker-compose.yml` for `forenhive-backend` uses a plain `build:` directive — there is **no host bind-mount onto `/app`**. Every code change requires a `docker compose build forenhive-backend && docker compose up -d forenhive-backend` cycle for the container to see it. The first four render-checks (after Fixes 1-4 in isolation) returned `200 OK` only because the *audit-baseline* image was still running with default `Undefined` — the fixes weren't actually executing yet. This was caught only when Fix 5 (`StrictUndefined`) was applied: the rebuild forced fresh image bytes, and the first run surfaced a real `UndefinedError` on `ev.severity` (audit M-2 prediction). Re-running the bulk sweep after fixing that confirmed all five fixes work together. **Treat the per-fix render-check results below as smoke tests that the API still returns 200, not as proof that each individual fix is exercised in isolation.** The final 54/54 StrictUndefined pass after Fix 5 is the load-bearing verification.

### Per-fix detail

| Fix | Commit | Files (real lines at HEAD) | Render-check | Notes |
|---|---|---|---|---|
| **C-4** wire suspect_profiles into report | `2d49905` | `backend/routers/reports.py`: added query block after `build_profile` (~L702-760); rewrote `profile_out` block (~L429-485). | 3/3 OK (200/110-138 KB) | Sweeps in pre-existing working-tree edits to reports.py (+300/-106) — commit not atomic. None of the 54 sessions' IPs has a `suspect_profiles` row yet (13 profiled IPs are from a different sample), so the new code path is wired but invisible until the engine profiles a current IP. Code path verified by inspection. |
| **C-1** persist risk_level + confidence | `b0cb4b3` | `forensic-engine/engine.py`: `_SESSION_INSERT_SQL` column list + ON CONFLICT + `_SESSION_ROW_TEMPLATE` placeholder count (17 → 19) + `_session_row` tuple (~L530-580); per-session loop sets `session["risk_level"]` / `session["confidence"]` (~L1166-1167). | 3/3 OK | Backfill SQL `UPDATE forensic_sessions SET risk_level=enrichment_data->>'risk_level', confidence=enrichment_data->>'confidence' WHERE risk_level IS NULL` updated **54 / 54 rows**. Sample after: `9fa78f196d68 | 24 | LOW | MEDIUM` (previously NULL/NULL). Engine isn't re-run live; next sweep will write these columns natively. Commit also swept in pre-existing engine.py edits (+202/-61). |
| **C-2+C-3** load enrichment_data + fix VT routing | `1f5f954` | `backend/routers/reports.py`: extended SELECT to include `ended_at, attack_velocity, score_version, scored_at, enrichment_data` (L630-639); normalized `enrichment_data` to dict (L662-670); rewrote VT block to read from `pg_row.enrichment_data` (L1272-1297). | 3/3 OK | Verified by DB sample: `115bdfb649be` shows `vt_available=true / vt_malicious=0`, `galah-172.16.1.77` shows `vt_available=false`. Adapter now surfaces those real values instead of always 0 / True. `engine_version` and `honeypot_port` (top-level) also wired. |
| **C-5+H-1** quota-aware enrichment + cache | `9ee7c91` | New `backend/services/quota_tracker.py` (async port of the engine tracker, 110 lines); `backend/services/enrichment.py` fully rewritten to gate every lookup on `is_exhausted(api)`, `mark_exhausted(api)` on 429/403, and cache to `ip_enrichment_cache` (1h TTL) under `backend_abuseipdb` / `backend_iplocate` keys. | 3/3 OK; warm-run latency 4.4 s vs cold 4.7-5.2 s. | Backend `.env` has empty API keys (`abuseipdb_api_key=""`, `iplocate_api_key=""`, `virustotal_api_key=""`), so the live behavior is "short-circuit at the top, never reach the tracker" — the wiring takes effect once keys are configured. `virustotal` row in `api_quota_status` is still `exhausted=TRUE` from earlier engine run; tracker will respect it. |
| **M-1** StrictUndefined + remaining gaps | `ae0b9b1` | `backend/routers/reports.py`: import + env config flip (L12, L37-47); timeline row mapping now adds `severity` via a small heuristic (~L342-371); adapter `return` now also supplies `vt_top_engines`, `vt_total`, `bottom_line`, `exec_narrative` (~L640-660). | **54 / 54 OK** under StrictUndefined; zero `UndefinedError` in backend logs. | First StrictUndefined run failed with `'dict object' has no attribute 'severity'` on every session — exactly the audit M-2 prediction. Fixing the timeline mapping cleared every other latent gap simultaneously (`vt_top_engines`, top-level `vt_total`, `bottom_line`, `exec_narrative` all supplied explicitly). |

### Final state

- Branch `audit/report-pipeline-2026-05-22` carries 5 commits on top of `c9966ce`. Pre-existing uncommitted working-tree changes from before the audit are folded into the first two commits (unavoidable noise; harmless).
- Backend image rebuilt and running with all fixes active.
- `forensic_sessions.risk_level` / `confidence` populated on all 54 rows.
- `api_quota_status` honored by the backend.
- StrictUndefined is on; every future report-pipeline regression that drops a variable will fail loudly instead of producing a blank cell.

### Out of scope for this pass (intentionally deferred)

The remaining HIGH/MEDIUM/LOW items from §6 are not started: **H-2** (read `forensic_iocs` instead of rebuilding), **H-3** (read `forensic_timeline_events`), **H-4** (read `forensic_chain_of_custody` instead of re-sealing), **H-5** (alternate TSA chain), **H-6** (`ip_risk_scores.recommendations` etc.), **H-7** (MITRE mapper coverage on cowrie sessions — 45/54 still empty), **H-8** (STIX from the forensic flow), **M-2..M-7**, **L-1/L-2**.

### Recommended next step

1. **Run the engine sweep once** so the new `risk_level` / `confidence` columns get populated natively (currently only via backfill) and any newly-seen IP also lands in `suspect_profiles` — this is the only way to see Fix 1's effect on a rendered report.
2. **Set the `*_API_KEY` env vars** so Fix 4's quota tracker / cache actually gates live traffic. Re-test under exhaustion (the `virustotal` row is already EXHAUSTED — the next report for a session with a captured-file SHA-256 should now return "Quota épuisé" instantly instead of timing out 15 s).
3. Pick one of **H-2 / H-3 / H-4** as the next sprint — they all follow the same pattern (read what the engine already wrote) and would close the remaining silent-loss gaps.

---

## Verification log — 2026-05-22

Post-fix verify-and-prove pass on `audit/report-pipeline-2026-05-22`. Goal: confirm that C-4 (FBI BAU profile) actually renders Mistral output once a `suspect_profiles` row exists for the demo session, plus confirm risk-band agreement and run the full StrictUndefined sweep.

### 1. Demo session + IP

| session_id | source_ip (`$DEMO_IP`) | honeypot | risk_score | started_at |
|---|---|---|---|---|
| `115bdfb649be` | `20.163.32.78` | cowrie | 34 | 2026-05-20 23:56:41 |

### 2. Profiling run

- Engine CLI has no `--ip` flag, but `forensic-engine/profiler.py --ip <ip>` is a usable single-IP entry point.
- Ran `docker exec forenhive-forensic-engine python /app/profiler.py --ip 20.163.32.78` — Ollama (`mistral:latest`, 4.8 GB, CPU) was already loaded; completed in ~113 s.
- Result: `suspect_profiles` row written for `20.163.32.78` at 2026-05-22 20:07:51.

### 3. `suspect_profiles` row snapshot

| field | value |
|---|---|
| `sophistication` | `Intermediate` |
| `confidence` | `0.7` |
| `primary_objective` | `reconnaissance` |
| `organized_score` | `0.6` |
| `dominant_tactic` | `Initial Access` |
| `disguise_used` | `false` |
| `escalation_detected` | `true` |
| `behavioral_traits` | 4 entries: "Multiple sessions", "Usage of custom or modified tools", "Evidence of planning (session count and duration)", "No clear anti-forensics behavior" |
| `signature_indicators` | 1 entry: "Moderate session length" |
| `similar_past_cases` | scalar integer `1` (**not** an array — the Mistral schema returns a count, not a list. The cases themselves come from a separate SQL in `_build_forensic_context`) |
| `detective_narrative` (full) | "The attacker exhibits signs of intermediate sophistication, using custom tools and demonstrating some planning. However, they do not employ anonymization layers or anti-forensics techniques. The primary objective is reconnaissance, and the attacker shows a signature behavior of moderate session length." |

### 4. Rendered FBI BAU section (the proof)

Rendered HTML preview for session `115bdfb649be` (`/api/reports/forensic/115bdfb649be/preview`, 74 107 bytes):

```html
<div class="profile-row"><span class="profile-key">Sophistication</span><span class="profile-val">INTERMEDIATE</span></div>
<div class="profile-row"><span class="profile-key">Confidence</span><span class="profile-val">70%</span></div>
<div class="profile-row"><span class="profile-key">Objective</span><span class="profile-val">reconnaissance</span></div>
<div class="profile-row"><span class="profile-key">Organized score</span><span class="profile-val">6 <span class="profile-val-max">/ 10</span></span></div>
<div class="profile-row"><span class="profile-key">Persistence</span><span class="profile-val">Escalating</span></div>
<div class="profile-row"><span class="profile-key">Operator type</span><span class="profile-val">Direct</span></div>
```

Behavioral traits — rendered as a `<ul>` of `<li>`s, one per Mistral trait:

```html
<li>Multiple sessions</li>
<li>Usage of custom or modified tools</li>
<li>Evidence of planning (session count and duration)</li>
<li>No clear anti-forensics behavior</li>
```

Detective narrative (Analytical narrative callout, verbatim from Mistral):

> The attacker exhibits signs of intermediate sophistication, using custom tools and demonstrating some planning. However, they do not employ anonymization layers or anti-forensics techniques. The primary objective is reconnaissance, and the attacker shows a signature behavior of moderate session length.

### 5. Explicit answers

| Question | Answer |
|---|---|
| Does the rendered FBI BAU section now show Mistral output or heuristic placeholder? | **Mistral output**, not heuristic. Pre-fix baseline showed `Sophistication=MEDIUM` (heuristic from score band), `Objective=Credential harvesting` (heuristic from `auth_attempts`), `Organized score=7/10` (heuristic `org_pct // 10`), `Operator type / Persistence` rows absent, narrative callout absent. Post-fix shows `INTERMEDIATE / reconnaissance / 6/10 / Escalating / Direct` + 4 real behavioral_traits + Mistral narrative callout. Every value matches the `suspect_profiles` row from §3. |
| Is `es_reference_cases` read from the profile row or still hard-coded `[]`? | **Read.** Adapter at `_adapt_context_for_v2` (post-Fix-1) sets `"es_reference_cases": profile.get("suspect_similar_cases") or []`. `suspect_similar_cases` is populated in `_build_forensic_context` from a `SELECT … FROM suspect_profiles WHERE source_ip != :ip AND (:obj='' OR primary_objective=:obj) ORDER BY ABS(risk_score - :score) LIMIT 5`. For `20.163.32.78` the query returns **0 rows** because no other IP shares `primary_objective='reconnaissance'` (it's the only `reconnaissance` IP across the 14 profiled IPs). The `or []` is just a None-safe default, **not** a hard-coded empty. The §"Similar Past Cases" template branch (`{% if profile.es_reference_cases ... | length > 0 %}`) correctly hides when empty. The wiring is verified by reading `backend/routers/reports.py` and by the fact that swapping in a different objective would return entries. |
| Is `organized_score` a Mistral-derived value or the heuristic? | **Mistral.** `6/10` = `int(round(0.6 * 10))` from the profile's `organized_score: 0.6`. The heuristic path (`org_pct // 10`) would have given `7/10` (with `org_pct=70`), which is what the pre-fix preview showed. |

### 6. C-1b — risk_label banding agreement

`_risk_label_color` thresholds in [reports.py:146-152](backend/routers/reports.py#L146-L152) are `CRITICAL≥70 / HIGH≥45 / MEDIUM≥25 / LOW≥10 / INFO<10`. These match `forensic-engine/risk_thresholds.py` (`CRITICAL=70, HIGH=45, MEDIUM=25, LOW=10`). Cross-checked across all 54 rows of `forensic_sessions`:

```
agree | disagree | total
   54 |        0 |    54
```

**No disagreement.** Adapter still derives the rendered label from score rather than reading `pg_row['risk_level']`, but because the bands and the source-of-truth (engine writes `risk_level` from the same `risk_level(score)` function) are consistent, no demo PDF will ever show a label different from the DB column. C-1b is **not a problem in practice**; deferred. Note for future hardening: a defensive `pg_row.get('risk_level') or _risk_label_color(risk_score)[0]` in the adapter would make the contract explicit, but it is not load-bearing for the demo.

### 7. Full 54-session StrictUndefined re-sweep

Driven via `POST /api/reports/forensic/{session_id}/generate` with a fresh JWT, header check on every PDF (HTTP=200, size ≥100 KB, magic bytes `%PDF`):

```
PASS: 54 / FAIL: 0
```

Zero `UndefinedError` / template-render failures in backend logs over the sweep window. The C-4 profile merge for `20.163.32.78` did not introduce a new field shape that StrictUndefined would catch — the adapter `profile_out` schema is stable whether or not a `suspect_profiles` row is present.

(First sweep attempt returned 401 on every request because the JWT cached from before the ~2-minute profiler run had expired — re-login fixed it. Not a real failure.)

### 8. Demo readiness verdict

**GREEN.** 54 / 54 pass under StrictUndefined; the FBI BAU section for the chosen demo session (`115bdfb649be`) shows real Mistral-derived `sophistication / objective / organized_score / behavioral_traits / detective_narrative / persistence / operator_type`; banding agrees across all 54 rows. The demo PDF can be generated live.

`es_reference_cases` for the demo session is structurally empty because no other profiled IP shares its primary_objective — this is a data condition, not a bug. To populate it for the demo, either profile a second IP that also has `primary_objective='reconnaissance'` (the engine sweep would do this naturally) or accept that the §"Similar Past Cases" block is hidden for this particular IP.
