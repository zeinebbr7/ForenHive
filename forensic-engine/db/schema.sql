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

-- Suspect profiles (aggregated per IP, built by LLM)
CREATE TABLE IF NOT EXISTS suspect_profiles (
    id          SERIAL      PRIMARY KEY,
    source_ip   VARCHAR(45) NOT NULL,
    profile     JSONB       NOT NULL,
    risk_score  INTEGER     CHECK (risk_score >= 0 AND risk_score <= 100),
    created_at  TIMESTAMP   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_profiles_source_ip   ON suspect_profiles (source_ip);
CREATE INDEX IF NOT EXISTS idx_profiles_risk_score  ON suspect_profiles (risk_score DESC);
