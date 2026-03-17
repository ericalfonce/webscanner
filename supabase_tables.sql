-- ============================================================
-- MulikaScans — Supabase PostgreSQL Schema
-- Run this in: Supabase Dashboard → SQL Editor → New Query
-- ============================================================

-- ── Users ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id                      SERIAL PRIMARY KEY,
    email                   VARCHAR(255) UNIQUE NOT NULL,
    username                VARCHAR(80)  UNIQUE,
    password_hash           VARCHAR(255),
    supabase_uid            VARCHAR(255) UNIQUE,

    role                    VARCHAR(20)  NOT NULL DEFAULT 'free',

    email_verified          BOOLEAN      DEFAULT FALSE,
    verification_token      VARCHAR(255),

    reset_token             VARCHAR(255),
    reset_token_expiry      TIMESTAMPTZ,

    stripe_customer_id      VARCHAR(255),
    subscription_id         VARCHAR(255),
    subscription_status     VARCHAR(50),

    created_at              TIMESTAMPTZ  DEFAULT NOW(),
    updated_at              TIMESTAMPTZ  DEFAULT NOW(),
    last_login              TIMESTAMPTZ,

    scan_count_this_month   INTEGER      DEFAULT 0,
    monthly_scan_limit      INTEGER      DEFAULT 2,

    phone_number            VARCHAR(30),
    profile_picture         VARCHAR(512),

    two_factor_secret       VARCHAR(64),
    two_factor_enabled      BOOLEAN      DEFAULT FALSE
);

-- ── Scans ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scans (
    id                      SERIAL PRIMARY KEY,
    user_id                 INTEGER      NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    target_url              VARCHAR(2048) NOT NULL,
    scan_type               VARCHAR(20)  NOT NULL DEFAULT 'quick',
    status                  VARCHAR(20)  NOT NULL DEFAULT 'queued',

    started_at              TIMESTAMPTZ,
    completed_at            TIMESTAMPTZ,
    duration_seconds        FLOAT,

    total_vulnerabilities   INTEGER      DEFAULT 0,
    critical_count          INTEGER      DEFAULT 0,
    high_count              INTEGER      DEFAULT 0,
    medium_count            INTEGER      DEFAULT 0,
    low_count               INTEGER      DEFAULT 0,
    info_count              INTEGER      DEFAULT 0,

    scan_config             JSONB,
    progress_percentage     INTEGER      DEFAULT 0,
    report_pdf_path         VARCHAR(512),

    created_at              TIMESTAMPTZ  DEFAULT NOW()
);

-- ── Vulnerabilities ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id                      SERIAL PRIMARY KEY,
    scan_id                 INTEGER      NOT NULL REFERENCES scans(id) ON DELETE CASCADE,

    name                    VARCHAR(255) NOT NULL,
    description             TEXT,
    severity                VARCHAR(20)  NOT NULL DEFAULT 'info',

    cvss_score              FLOAT,
    cvss_vector             VARCHAR(255),
    category                VARCHAR(50),

    url_affected            VARCHAR(2048),
    parameter               VARCHAR(255),
    evidence                TEXT,
    request_data            TEXT,
    response_data           TEXT,
    remediation             TEXT,
    "references"            JSONB,

    false_positive          BOOLEAN      DEFAULT FALSE,
    status                  VARCHAR(30)  NOT NULL DEFAULT 'open',

    cwe_id                  VARCHAR(20),
    owasp_category          VARCHAR(50),
    discovered_at           TIMESTAMPTZ  DEFAULT NOW()
);

-- ── Subscriptions ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS subscriptions (
    id                          SERIAL PRIMARY KEY,
    user_id                     INTEGER      NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    plan                        VARCHAR(20)  NOT NULL DEFAULT 'free',
    stripe_subscription_id      VARCHAR(255) UNIQUE,
    stripe_customer_id          VARCHAR(255),
    flw_subscription_id         VARCHAR(255),
    billing_cycle               VARCHAR(10)  DEFAULT 'monthly',
    status                      VARCHAR(30)  NOT NULL DEFAULT 'active',

    current_period_start        TIMESTAMPTZ,
    current_period_end          TIMESTAMPTZ,
    created_at                  TIMESTAMPTZ  DEFAULT NOW(),
    cancelled_at                TIMESTAMPTZ
);

-- ── Payments ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS payments (
    id                          SERIAL PRIMARY KEY,
    user_id                     INTEGER      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    subscription_id             INTEGER      REFERENCES subscriptions(id),

    stripe_payment_intent_id    VARCHAR(255) UNIQUE,
    flw_tx_ref                  VARCHAR(255),
    flw_transaction_id          VARCHAR(255),
    payment_method              VARCHAR(50),
    amount_cents                INTEGER      NOT NULL,
    currency                    VARCHAR(10)  NOT NULL DEFAULT 'usd',
    status                      VARCHAR(30)  NOT NULL DEFAULT 'pending',

    created_at                  TIMESTAMPTZ  DEFAULT NOW()
);

-- ── Scan Schedules ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scan_schedules (
    id                  SERIAL PRIMARY KEY,
    user_id             INTEGER      NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    target_url          VARCHAR(2048) NOT NULL,
    scan_type           VARCHAR(20)  NOT NULL DEFAULT 'quick',
    cron_expression     VARCHAR(100) NOT NULL,
    is_active           BOOLEAN      DEFAULT TRUE,

    last_run            TIMESTAMPTZ,
    next_run            TIMESTAMPTZ,
    created_at          TIMESTAMPTZ  DEFAULT NOW()
);

-- ── Indexes ───────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS ix_users_email          ON users(email);
CREATE INDEX IF NOT EXISTS ix_users_supabase_uid   ON users(supabase_uid);
CREATE INDEX IF NOT EXISTS ix_scans_user_id        ON scans(user_id);
CREATE INDEX IF NOT EXISTS ix_scans_status         ON scans(status);
CREATE INDEX IF NOT EXISTS ix_vuln_scan_id         ON vulnerabilities(scan_id);
CREATE INDEX IF NOT EXISTS ix_vuln_severity        ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS ix_sub_user_id          ON subscriptions(user_id);
CREATE INDEX IF NOT EXISTS ix_pay_user_id          ON payments(user_id);
CREATE INDEX IF NOT EXISTS ix_sched_user_id        ON scan_schedules(user_id);

-- ── Auto-update updated_at ────────────────────────────────────
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS users_updated_at ON users;
CREATE TRIGGER users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ── Row Level Security (optional — enable if needed) ──────────
-- ALTER TABLE users          ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE scans          ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE vulnerabilities ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE subscriptions  ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE payments       ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE scan_schedules ENABLE ROW LEVEL SECURITY;
