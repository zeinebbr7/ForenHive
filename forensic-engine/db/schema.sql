-- ForenHive — Sprint 3 PostgreSQL Schema
-- Run via: forensic-engine/db/init_db.py

-- IP enrichment cache (24h TTL)
CREATE TABLE IF NOT EXISTS ip_enrichment_cache (
    ip          VARCHAR(45) PRIMARY KEY,
    data        JSONB       NOT NULL,
    cached_at   TIMESTAMP   NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMP   NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ip_cache_expires ON ip_enrichment_cache (expires_at);

-- Malware file analysis results
CREATE TABLE IF NOT EXISTS file_analysis (
    sha256              VARCHAR(64) PRIMARY KEY,
    virustotal_result   JSONB,
    yara_matches        JSONB,
    analyzed_at         TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Forensic sessions (one per attacker session)
CREATE TABLE IF NOT EXISTS forensic_sessions (
    session_id          VARCHAR(100) PRIMARY KEY,
    honeypot_type       VARCHAR(20),
    source_ip           VARCHAR(45),
    started_at          TIMESTAMP,
    ended_at            TIMESTAMP,
    risk_score          INTEGER CHECK (risk_score >= 0 AND risk_score <= 100),
    mitre_techniques    JSONB,
    enrichment_data     JSONB,
    kill_chain_phase    VARCHAR(50),
    kill_chain_stage    INTEGER,
    primary_technique   VARCHAR(20),
    forensic_narrative  TEXT,
    created_at          TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Migration: add new columns to existing deployments
ALTER TABLE forensic_sessions ADD COLUMN IF NOT EXISTS kill_chain_phase   VARCHAR(50);
ALTER TABLE forensic_sessions ADD COLUMN IF NOT EXISTS kill_chain_stage   INTEGER;
ALTER TABLE forensic_sessions ADD COLUMN IF NOT EXISTS primary_technique  VARCHAR(20);
ALTER TABLE forensic_sessions ADD COLUMN IF NOT EXISTS forensic_narrative TEXT;
-- updated_at tracks last re-score; used by CoC to detect stale seals
ALTER TABLE forensic_sessions ADD COLUMN IF NOT EXISTS updated_at         TIMESTAMP;

-- Unified risk scoring (Option A) — one row per IP aggregating all honeypots
ALTER TABLE forensic_sessions ADD COLUMN IF NOT EXISTS risk_level      VARCHAR(20);   -- CRITIQUE|ÉLEVÉ|MOYEN|FAIBLE|INFO
ALTER TABLE forensic_sessions ADD COLUMN IF NOT EXISTS confidence      VARCHAR(10);   -- HIGH|MEDIUM|LOW
ALTER TABLE forensic_sessions ADD COLUMN IF NOT EXISTS signal_breakdown JSONB;        -- 6-signal breakdown JSON
ALTER TABLE forensic_sessions ADD COLUMN IF NOT EXISTS honeypots_hit   TEXT[];        -- ['cowrie','dionaea']
ALTER TABLE forensic_sessions ADD COLUMN IF NOT EXISTS honeypot_count  INT DEFAULT 1;
ALTER TABLE forensic_sessions ADD COLUMN IF NOT EXISTS sessions_count  INT DEFAULT 1;
ALTER TABLE forensic_sessions ADD COLUMN IF NOT EXISTS scored_at       TIMESTAMP;    -- last unified scoring time
ALTER TABLE forensic_sessions ADD COLUMN IF NOT EXISTS login_attempts  INT   DEFAULT 0;
ALTER TABLE forensic_sessions ADD COLUMN IF NOT EXISTS success_count   INT   DEFAULT 0;
ALTER TABLE forensic_sessions ADD COLUMN IF NOT EXISTS attack_velocity FLOAT DEFAULT 0.0;

CREATE INDEX IF NOT EXISTS idx_sessions_source_ip    ON forensic_sessions (source_ip);
CREATE INDEX IF NOT EXISTS idx_sessions_risk_score   ON forensic_sessions (risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_honeypot     ON forensic_sessions (honeypot_type);
CREATE INDEX IF NOT EXISTS idx_sessions_started_at   ON forensic_sessions (started_at DESC);

-- External API quota tracker (persistent across forensic-engine runs)
-- Used to skip calls to rate-limited APIs once their daily quota is exhausted,
-- instead of burning retries every run. Reset time is stored in UTC.
CREATE TABLE IF NOT EXISTS api_quota_status (
    api_name     VARCHAR(32) PRIMARY KEY,
    exhausted    BOOLEAN     NOT NULL DEFAULT FALSE,
    reset_at     TIMESTAMPTZ,
    last_error   TEXT,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Forensic timeline: per-IP unified event stream across all honeypots + Zeek.
-- One row per atomic event (connect, login, command, http request, file drop,
-- conn.log, weird, scan…). Enables cross-honeypot reconstruction of an
-- attacker's activity with millisecond precision.
CREATE TABLE IF NOT EXISTS forensic_timeline_events (
    id                BIGSERIAL    PRIMARY KEY,
    source_ip         VARCHAR(45)  NOT NULL,
    ts                TIMESTAMPTZ  NOT NULL,
    honeypot_type     VARCHAR(20)  NOT NULL,
    event_category    VARCHAR(32)  NOT NULL,
    event_action      VARCHAR(64)  NOT NULL,
    session_id        VARCHAR(100),
    destination_port  INTEGER,
    protocol          VARCHAR(16),
    summary           TEXT,
    raw               JSONB,
    es_doc_id         VARCHAR(64)  UNIQUE,
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_timeline_ip_ts       ON forensic_timeline_events (source_ip, ts);
CREATE INDEX IF NOT EXISTS idx_timeline_ts          ON forensic_timeline_events (ts DESC);
CREATE INDEX IF NOT EXISTS idx_timeline_honeypot    ON forensic_timeline_events (honeypot_type);
CREATE INDEX IF NOT EXISTS idx_timeline_session     ON forensic_timeline_events (session_id);
CREATE INDEX IF NOT EXISTS idx_timeline_category    ON forensic_timeline_events (event_category);

-- Forensic IoCs: structured indicators extracted from timeline events.
-- Each row = one unique (type, value, source_ip) tuple, with seen counts
-- and provenance. Enables fast pivots ("all URLs from attacker X") and
-- threat-intel export (STIX / MISP).
CREATE TABLE IF NOT EXISTS forensic_iocs (
    id             BIGSERIAL   PRIMARY KEY,
    ioc_type       VARCHAR(24) NOT NULL,
    ioc_value      TEXT        NOT NULL,
    source_ip      VARCHAR(45) NOT NULL,
    honeypot_types TEXT[]      NOT NULL DEFAULT '{}',
    first_seen     TIMESTAMPTZ NOT NULL,
    last_seen      TIMESTAMPTZ NOT NULL,
    occurrences    INTEGER     NOT NULL DEFAULT 1,
    context        JSONB,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (ioc_type, ioc_value, source_ip)
);

CREATE INDEX IF NOT EXISTS idx_iocs_source_ip ON forensic_iocs (source_ip);
CREATE INDEX IF NOT EXISTS idx_iocs_type      ON forensic_iocs (ioc_type);
CREATE INDEX IF NOT EXISTS idx_iocs_value     ON forensic_iocs (ioc_value);
CREATE INDEX IF NOT EXISTS idx_iocs_last_seen ON forensic_iocs (last_seen DESC);

-- Forensic chain of custody: SHA-256 seal + hash chain + RFC 3161 timestamp
-- for each forensic_session. Tampering with a sealed session is detectable
-- because (a) the canonical hash no longer matches and (b) the prev_hash
-- chain breaks at the altered record, invalidating everything downstream.
-- Batched RFC 3161 timestamps (Merkle root) bind the chain head to a
-- certified wall-clock time from a public TSA.
CREATE TABLE IF NOT EXISTS forensic_chain_of_custody (
    id              BIGSERIAL    PRIMARY KEY,
    session_id      VARCHAR(100) NOT NULL UNIQUE REFERENCES forensic_sessions(session_id) ON DELETE CASCADE,
    record_hash     CHAR(64)     NOT NULL,
    prev_hash       CHAR(64),
    canonical_json  JSONB        NOT NULL,
    batch_id        BIGINT,
    sealed_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_coc_session    ON forensic_chain_of_custody (session_id);
CREATE INDEX IF NOT EXISTS idx_coc_sealed_at  ON forensic_chain_of_custody (sealed_at);
CREATE INDEX IF NOT EXISTS idx_coc_batch      ON forensic_chain_of_custody (batch_id);

-- RFC 3161 batch timestamps: one row per TSA request, binding a Merkle root
-- of all records sealed in that batch to a trusted time from a public TSA.
CREATE TABLE IF NOT EXISTS forensic_coc_batches (
    id             BIGSERIAL    PRIMARY KEY,
    merkle_root    CHAR(64)     NOT NULL,
    record_count   INTEGER      NOT NULL,
    tsa_provider   VARCHAR(128) NOT NULL,
    tsa_time       TIMESTAMPTZ,
    tsa_response   BYTEA,
    tsa_status     VARCHAR(32)  NOT NULL,
    tsa_error      TEXT,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_coc_batch_time ON forensic_coc_batches (tsa_time);

-- Suspect profiles (aggregated per IP, built by LLM)
CREATE TABLE IF NOT EXISTS suspect_profiles (
    id          SERIAL      PRIMARY KEY,
    source_ip   VARCHAR(45) NOT NULL UNIQUE,
    profile     JSONB       NOT NULL,
    risk_score  INTEGER     CHECK (risk_score >= 0 AND risk_score <= 100),
    created_at  TIMESTAMP   NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMP   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_profiles_source_ip   ON suspect_profiles (source_ip);
CREATE INDEX IF NOT EXISTS idx_profiles_risk_score  ON suspect_profiles (risk_score DESC);

-- Migration: ensure UNIQUE constraint exists on existing deployments
DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'suspect_profiles_source_ip_key'
    ) THEN
        ALTER TABLE suspect_profiles ADD CONSTRAINT suspect_profiles_source_ip_key UNIQUE (source_ip);
    END IF;
END $$;
ALTER TABLE suspect_profiles ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP NOT NULL DEFAULT NOW();

-- Create postgres superuser role so standard DBA tools work
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'postgres') THEN
        CREATE ROLE postgres SUPERUSER LOGIN;
    END IF;
END $$;

-- Aggregated per-IP risk scores (Phase 9 unified scoring)
-- Created separately from forensic_sessions to avoid PK conflicts.
-- See docs/schema_risk.sql for the standalone migration script.
CREATE TABLE IF NOT EXISTS ip_risk_scores (
    source_ip           INET PRIMARY KEY,
    risk_score          INT NOT NULL DEFAULT 0,
    risk_level          VARCHAR(20) NOT NULL,
    confidence          VARCHAR(10) NOT NULL,
    active_signals      INT DEFAULT 0,
    signal_breakdown    JSONB NOT NULL DEFAULT '{}',
    honeypots_hit       TEXT[] DEFAULT '{}',
    honeypot_count      INT DEFAULT 1,
    honeypot_summary    JSONB DEFAULT '{}',
    sessions_count      INT DEFAULT 1,
    key_findings        TEXT[] DEFAULT '{}',
    recommendations     JSONB DEFAULT '[]'::jsonb,
    enrichment_snapshot JSONB DEFAULT '{}',
    scored_at           TIMESTAMP DEFAULT NOW(),
    updated_at          TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ip_risk_score  ON ip_risk_scores(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_ip_risk_level  ON ip_risk_scores(risk_level);
CREATE INDEX IF NOT EXISTS idx_ip_risk_scored ON ip_risk_scores(scored_at DESC);

-- ─────────────────────────────────────────────────────────────────────────────
-- Risk score v2.0.0 migration
-- ─────────────────────────────────────────────────────────────────────────────

ALTER TABLE forensic_sessions
    ADD COLUMN IF NOT EXISTS score_version VARCHAR(16);

ALTER TABLE ip_risk_scores
    ADD COLUMN IF NOT EXISTS score_version VARCHAR(16);

-- Tag old rows so they're filterable
UPDATE forensic_sessions  SET score_version = '1.0.0' WHERE score_version IS NULL;
UPDATE ip_risk_scores     SET score_version = '1.0.0' WHERE score_version IS NULL;

-- Composite index for Phase 9 (audit fix P-5)
CREATE INDEX IF NOT EXISTS idx_sessions_ip_time
    ON forensic_sessions(source_ip, started_at DESC);

-- OPTIONAL: label backfill (commented out by default)
-- Uncomment ONLY if you want old rows displayed under v2 cutoffs in dashboards.
-- WARNING: this re-maps v1.0 scores using v2.0 cutoffs. The resulting labels
-- describe v2 cutoffs applied to v1-scale numbers — NOT what v2 would have
-- said about the same attacker. Old rows will appear to "jump tiers" because
-- the absolute scale shifted, not because their behavior was reassessed.
-- Filter dashboards by score_version='2.0.0' for apples-to-apples instead.
--
-- UPDATE forensic_sessions SET risk_level = CASE
--     WHEN risk_score >= 70 THEN 'CRITICAL'
--     WHEN risk_score >= 45 THEN 'HIGH'
--     WHEN risk_score >= 25 THEN 'MEDIUM'
--     WHEN risk_score >= 10 THEN 'LOW'
--     ELSE 'INFO' END
-- WHERE score_version = '1.0.0';
--
-- UPDATE ip_risk_scores SET risk_level = CASE
--     WHEN risk_score >= 70 THEN 'CRITICAL'
--     WHEN risk_score >= 45 THEN 'HIGH'
--     WHEN risk_score >= 25 THEN 'MEDIUM'
--     WHEN risk_score >= 10 THEN 'LOW'
--     ELSE 'INFO' END
-- WHERE score_version = '1.0.0';
