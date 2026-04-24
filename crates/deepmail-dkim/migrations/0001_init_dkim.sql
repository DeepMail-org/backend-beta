-- ============================================================================
-- deepmail-dkim: Initial schema
-- Tables owned exclusively by this service. No other service reads or writes.
-- ============================================================================

-- ── Per-email DKIM analysis results ─────────────────────────────────────────

CREATE TABLE IF NOT EXISTS dkim_analyses (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    email_id          UUID        NOT NULL,
    analyzed_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    replay_detected   BOOLEAN     NOT NULL DEFAULT false,
    replay_confidence REAL        NOT NULL DEFAULT 0.0,
    replay_reasons    TEXT[]      NOT NULL DEFAULT '{}',
    raw_result        JSONB       NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_dkim_analyses_email_id
    ON dkim_analyses(email_id);

-- ── Per-signature detail (one email can have multiple DKIM signatures) ──────

CREATE TABLE IF NOT EXISTS dkim_signatures (
    id                        UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    analysis_id               UUID        NOT NULL REFERENCES dkim_analyses(id) ON DELETE CASCADE,
    selector                  TEXT        NOT NULL,
    domain                    TEXT        NOT NULL,
    algorithm                 TEXT        NOT NULL,
    timestamp_signed          TIMESTAMPTZ,
    timestamp_expiry          TIMESTAMPTZ,
    body_hash_claimed         TEXT        NOT NULL,
    body_hash_computed        TEXT        NOT NULL,
    body_hash_match           BOOLEAN     NOT NULL,
    header_delta_seconds      BIGINT,
    receive_delta_seconds     BIGINT,
    key_status                TEXT        NOT NULL,
    key_rotated_since_signing BOOLEAN     NOT NULL DEFAULT false,
    signature_valid           BOOLEAN     NOT NULL DEFAULT false,
    created_at                TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_dkim_signatures_analysis_id
    ON dkim_signatures(analysis_id);

-- ── DNS key cache (avoid repeated lookups for the same selector/domain) ─────

CREATE TABLE IF NOT EXISTS dkim_key_cache (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    selector          TEXT        NOT NULL,
    domain            TEXT        NOT NULL,
    fetched_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at        TIMESTAMPTZ NOT NULL,
    txt_record        TEXT,
    public_key_base64 TEXT,
    algorithm         TEXT,
    found             BOOLEAN     NOT NULL,
    UNIQUE (selector, domain)
);

CREATE INDEX IF NOT EXISTS idx_dkim_key_cache_lookup
    ON dkim_key_cache(selector, domain, expires_at);
