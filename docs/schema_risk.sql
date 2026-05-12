-- ══════════════════════════════════════════════════════════════
-- ForenHive — Aggregated IP Risk Scores
-- One row per source_ip, upserted on each scoring run.
-- Separate from forensic_sessions (which stores per-session raw data).
-- ══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS ip_risk_scores (
    source_ip           INET PRIMARY KEY,

    -- Score
    risk_score          INT NOT NULL DEFAULT 0,         -- 0-100
    risk_level          VARCHAR(20) NOT NULL,            -- CRITICAL|HIGH|MEDIUM|LOW|INFO
    confidence          VARCHAR(10) NOT NULL,            -- HIGH|MEDIUM|LOW
    active_signals      INT DEFAULT 0,

    -- 6-signal breakdown (JSON)
    signal_breakdown    JSONB NOT NULL DEFAULT '{}',

    -- Honeypot aggregation
    honeypots_hit       TEXT[] DEFAULT '{}',             -- e.g. {cowrie,dionaea}
    honeypot_count      INT DEFAULT 1,
    honeypot_summary    JSONB DEFAULT '{}',
    sessions_count      INT DEFAULT 1,

    -- Analysis outputs
    key_findings        TEXT[] DEFAULT '{}',
    recommendations     JSONB DEFAULT '[]'::jsonb,

    -- Enrichment snapshot (geo, ASN, privacy flags at scoring time)
    enrichment_snapshot JSONB DEFAULT '{}',

    -- Timestamps
    scored_at           TIMESTAMP DEFAULT NOW(),
    updated_at          TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ip_risk_score    ON ip_risk_scores(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_ip_risk_level    ON ip_risk_scores(risk_level);
CREATE INDEX IF NOT EXISTS idx_ip_risk_scored   ON ip_risk_scores(scored_at DESC);
