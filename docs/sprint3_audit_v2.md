# Sprint 3 Audit — Risk Scoring v2.0.0 (9-Signal Model)

## Context

Sprint 3's forensic engine originally scored sessions with `risk_score_optimized.py`
— a model that had drifted into **two inconsistent entry points**: a 6-signal
`score_session_from_data()` (used by the backend test) and an 18-signal
`calculate_risk_score()` (used by `engine.py`, documented in
[sprint3_audit_final.md](sprint3_audit_final.md) §7). An audit found this
duplication, ad-hoc weighting, and ~5 enrichment fields that were collected but
never scored.

This work **replaced the whole thing** with a single, self-contained 9-signal
model — `forensic-engine/risk_score.py` v2.0.0 — that:
- uses the previously-ignored fields (geo country, Shodan vulns, bogon, HTTP paths, critical destination port),
- scores **command quality** (not just count) by fetching commands *before* scoring,
- derives YARA severity from rule metadata instead of a hardcoded family list,
- computes MITRE techniques *before* scoring so the sophistication signal works,
- maps the 9 signals onto 3 criminology buckets (WHO/WHAT/HOW) for the PFE Ch4 narrative,
- recalibrates label cutoffs and **decouples** them from operational thresholds.

This document is the reference audit: what changed, the 9 signals in detail, how
scoring works end-to-end, the engine integration, validation results, and open
findings. It is the companion to [sprint3_audit_final.md](sprint3_audit_final.md),
which describes the superseded v1 model.

---

## 1 · What changed (v1 → v2)

| Aspect | v1 (`risk_score_optimized.py`) | v2 (`risk_score.py`) |
|---|---|---|
| Entry points | 2 inconsistent (`score_session_from_data` 6-sig, `calculate_risk_score` 18-sig) | 2 coherent: `score_session()` + `score_ip()` |
| Signal count | 6 / 18 (depending on path) | **9**, summing to exactly **100** |
| Taxonomy | flat list | **WHO (33) · WHAT (43) · HOW (24)** — FBI-BAU framing |
| Output | plain `dict` | `ScoreResult` dataclass (+ `SignalDetail` per signal) |
| Command handling | count only | **quality tags** (credential-access / destructive / lateral) |
| YARA | hardcoded family→severity list | **severity from rule `meta`** (`List[{rule, severity}]`) |
| MITRE | mapped *after* scoring | mapped **before** (feeds `mitre_sophistication`) |
| Private-IP logic | ×2 behavioral multiplier | reputation + anonymization **skipped**; behavior still scores |
| Label cutoffs | 80 / 60 / 40 / 20 | **70 / 45 / 25 / 10** |
| Operational thresholds | derived from `HIGH` | **standalone** (decoupled) |
| Versioning | none | `SCORE_VERSION = "2.0.0"` tagged on every row |

Files touched:
- **New**: `forensic-engine/risk_score.py`, `forensic-engine/tests/test_risk_score.py` (+ `__init__.py`, `conftest.py`)
- **Rewritten**: `forensic-engine/risk_thresholds.py`
- **Edited**: `forensic-engine/engine.py` (edits A–F + score_version bugfix), `forensic-engine/mitre_mapper.py` (EDIT G `narrative_for`)
- **Migrated**: `backend/tests/test_risk_score.py` (to new API; 34 tests pass)
- **Schema**: `forensic-engine/db/schema.sql` (+`score_version` columns, `idx_sessions_ip_time`)
- **Deleted**: `forensic-engine/risk_score_optimized.py` + `__pycache__/`

---

## 2 · The 9 signals (exact mechanics)

Each signal is a pure function `(d: dict) -> SignalDetail` with fields
`points, max_points, label, category, detail, evidence, skipped, skip_reason`.
Inputs are coerced defensively. Constants live at the top of `risk_score.py`.

### WHO — attacker identity & trust (33 pts)

**1 · reputation (max 15)** — AbuseIPDB confidence, public IPs only.
- `is_private` → skipped (`skip_reason="private_ip"`).
- Buckets: ≥90→15, ≥70→11, ≥50→7, ≥25→4, else 0. Score clamped 0–100.
- Evidence: abuse_score, total_reports, distinct_users, categories.

**2 · anonymization (max 10)** — how hidden the origin is. Skipped for private.
- Priority: bogon→10, Tor→10, VPN/proxy→6, datacenter ASN→3, else 0.
- Evidence: the 5 booleans + ASN + org.

**3 · threat_history (max 8)** — prior/contextual badness, additive then capped at 8.
- recidivism: `min(4, int(2·log2(1+previous_sessions)))` when previously seen.
- `is_abuser_listed` +1; `threat_tier=="high"` +1.
- country: sanctioned {KP,IR,SY,CU,VE} +2, high-threat {RU,CN,BY} +1.
- Shodan vulns: `min(2, len(vulns))`.

### WHAT — attack behavior (43 pts)

**4 · intent_volume (max 10)** — effort + recon intent.
- effective attempts = attempts (cowrie) or attempts×0.5 (others); `base=min(6, int(2·log10(1+eff)))`.
- velocity bonus: >50→2, >10→1.
- scan-path bonus: `min(3, hits)` across `http_paths` ∪ `commands` vs `_SCAN_PATHS`.

**5 · compromise_depth (max 15)** — did they get in and what did they do.
- Returns 0 if `success_count==0 AND file_download_count==0`.
- auth: `int(5·log2(1+success))`; cmd volume: `min(3, command_count//3)`.
- **command quality** (`min(4)`): credential-access +3, destructive +2, lateral-cmd +1.
  - Per-session: regex over `commands` (`_CRED_/_DESTRUCTIVE_/_LATERAL_PATTERNS`).
  - IP-aggregate: reads pre-computed `command_quality_tags` (commands not re-aggregated).
- file ingress: `min(3, file_download_count)`.

**6 · exfiltration (max 8)** — egress volume. `min(8, int(2·log10(1+KB)))` from `exfil_bytes` (not payload_bytes). 0 → "no data egress".

**7 · lateral_movement (max 10)** — spread/escalation.
- CVE exploit +4, SMB share enum +2, epmapper prescan +2, ≥3 honeypots +2 (≥2 +1), critical destination port +2 (`{445,1433,3306,3389,5432,27017,6379,9200}`).

### HOW — capability/tooling (24 pts)

**8 · malware (max 12)** — **additive** YARA + VT.
- YARA severity → pts (critical 6, high 4, medium 2, low 1); takes the **max** rule. Legacy `List[str]` treated as medium.
- VT tiers: ≥20→6, ≥10→4, ≥1→2.

**9 · mitre_sophistication (max 12)** — breadth of TTPs.
- techniques: `min(6, distinct_count)`; kill-chain stage: `min(4, stage//2)`; distinct tactics: `min(2, tactics-1)`. Accepts technique IDs as strings or `{id|technique_id}` dicts.

**Confidence** = active signal count (points>0): ≥5 HIGH · ≥3 MEDIUM · else LOW.
**Final score** = `min(100, round(sum of points))`.

---

## 3 · How scoring works (data structures + orchestration)

- `SignalDetail` / `ScoreResult` dataclasses; `.to_dict()` for JSONB persistence.
- **`score_session(session_data) -> ScoreResult`** (Phase 3): runs the 9 signals in
  order, each wrapped in try/except (a raising signal becomes a 0-pt skipped detail),
  sums, sets confidence + `risk_level()` from `risk_thresholds`, `scorer_mode="session"`.
- **`score_ip(ip, sessions, enrichment) -> ScoreResult`** (Phase 9): empty → INFO
  result; otherwise builds a synthetic "super-session":
  - WHO from `enrichment` (reputation/threat_summary/geo/infrastructure);
  - WHAT: SUM login_attempts/success/command_count/exfil_bytes/file_downloads, MAX velocity;
  - quality: **union** of per-session `command_quality_tags` (raw commands not re-aggregated);
  - honeypot diversity union; SMB OR/MAX/union; HOW: concat YARA, MAX VT, first VT family, union techniques, kill-chain phase from the max-stage session;
  - `is_private=False`; then calls `score_session`, overrides `scorer_mode="ip_aggregate"` + `sessions_aggregated`.

`risk_thresholds.py` v2.0:
```
CRITICAL=70  HIGH=45  MEDIUM=25  LOW=10          # labels
ALERT_INDEX_MIN=40  ALERT_NOTIFY_MIN=60  PROFILE_RISK_MIN=50   # decoupled ops
```

---

## 4 · Engine integration (edits A–G + bugfix)

- **A** `engine.py:41` — import `score_session, score_ip, SCORE_VERSION` + `risk_level` from `risk_thresholds`.
- **B** `_load_file_analysis_from_pg` — preserve YARA severity: `{"rule", "severity": meta.severity|"medium"}`.
- **C** new `_query_cowrie_file_downloads()` (ES count of `cowrie.session.file_download`, T1105).
- **D** Phase 3 rewrite (`run_session_scoring`): fetch commands + file_downloads **before** scoring; run deterministic MITRE → feed scorer; call `score_session`; LLM narrative via `mitre.narrative_for()`; persist new fields into `enrichment_data` (signal_breakdown, score_version, smb/exploit/recidivism/shodan/geo/port) so Phase 9 can read them back.
- **E** Phase 9 rewrite (`run_full_analysis`): one pooled PG connection, narrowed SELECT, per-IP `enrichment` load, `score_ip`, store via `_store_unified_risk_score`.
- **F** `_store_unified_risk_score` — add `score_version` column to INSERT + ON CONFLICT.
- **G** `mitre_mapper.narrative_for(session, technique_ids)` — narrative-only (avoids re-deriving techniques + double LLM call); mirrors `map_session` shape incl. Ollama-down fallback.
- **Bugfix** (found during validation): the session-save path never wrote the top-level `forensic_sessions.score_version` column. Added it to `_SESSION_INSERT_SQL` (cols + ON CONFLICT), `_SESSION_ROW_TEMPLATE`, `_session_row` (`session.get("score_version") or SCORE_VERSION`), and set `session["score_version"]` in Phase 3.

SQL migration (idempotent): `ADD COLUMN IF NOT EXISTS score_version` on
`forensic_sessions` + `ip_risk_scores`; backfill old rows to `1.0.0`;
`CREATE INDEX idx_sessions_ip_time (source_ip, started_at DESC)`. Label re-mapping
of old rows is **commented out** with a warning (re-mapping v1 scores under v2 cutoffs
is not "what v2 would have said").

---

## 5 · Validation results

- **Unit tests**: forensic-engine `tests/test_risk_score.py` **76 pass**; backend `tests/test_risk_score.py` migrated to v2 API **34 pass**.
- **Real run** (`engine.py --hours 24`, 50 Cowrie sessions): completes ~77 s with LLM disabled; 9 signals present per session; `score_ip` aggregates correctly.
- **Container**: image rebuilt + restarted; new code baked in; `risk_level(25)=MEDIUM` confirmed in-container; old scorer absent.
- **Scale observation (by design)**: individual Cowrie sessions land LOW/MEDIUM; the per-IP aggregate escalates (volume sums across sessions) — exactly the WHO+WHAT+HOW aggregation intent.

---

## 6 · Open findings / caveats

1. **`forensic_sessions.risk_level` top-level column is blank** — *pre-existing*, not a v2 regression. The session INSERT never populated it; the canonical level lives in `enrichment_data->>'risk_level'` (correct). Left as a reported finding (writing it would change data the walled-off backend/frontend consume).
2. **`score_version` column can mislead on un-rescored rows** — the `_session_row` fallback stamps `SCORE_VERSION` on every save, so a row whose JSONB is still old-shape (no `active_signals`/`confidence`, old-threshold level) can show `score_version=2.0.0`. Resolved by a clean full re-score that overwrites JSONB.
3. **Stale mixed-threshold rows** can appear from runs predating a rebuild; a full `--hours 24` run on the baked image overwrites them. Recommended: run one clean full analysis and confirm `score==level` consistency + `active_signals` present on all rows.
4. **`server.py` scheduler** runs `engine.py` every `ENGINE_INTERVAL_MINUTES` (currently 5 min) and is **not** mutually exclusive with manual `docker exec` runs — avoid manual runs while a scheduled run is active to prevent interleaved writes.
5. **Backend consumers** (`report_adapter.py`, `reports.py`) still reference the old 6-signal JSONB shape in comments — verify they read the new `signal_breakdown` keys before Sprint 4 surfaces them.

---

## 7 · Verification (how to confirm end-to-end)

```bash
# unit tests
cd forensic-engine && python3 -m pytest tests/test_risk_score.py -q   # 76 pass
cd backend        && python3 -m pytest tests/test_risk_score.py -q   # 34 pass

# clean full re-score on the rebuilt container, then consistency check
docker exec -d forenhive-forensic-engine python -u engine.py --hours 24
docker exec -i forenhive-postgresql psql -U forenhive -d forenhive -c "
  SELECT risk_score, enrichment_data->>'risk_level' lvl,
         (enrichment_data->>'active_signals') IS NOT NULL has_active, count(*)
  FROM forensic_sessions GROUP BY 1,2,3 ORDER BY 1 DESC;"
# expect: every row's lvl matches risk_thresholds(risk_score) AND has_active = t

# per-IP aggregate sanity
docker exec -i forenhive-postgresql psql -U forenhive -d forenhive -c "
  SELECT source_ip, risk_score, risk_level, score_version,
         (SELECT count(*) FROM jsonb_object_keys(signal_breakdown)) n_sig
  FROM ip_risk_scores ORDER BY risk_score DESC;"   # n_sig = 9, level matches score
```

---

**Audit author:** Claude Code (Opus 4.7) · **Model version:** risk_score v2.0.0 · **Supersedes:** the v1 18/6-signal model in [sprint3_audit_final.md](sprint3_audit_final.md) §7.
