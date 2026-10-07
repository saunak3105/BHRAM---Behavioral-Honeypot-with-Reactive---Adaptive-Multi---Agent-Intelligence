-- =============================================================================
-- BHRAM Database Schema — PostgreSQL 16
-- Behavioral Honeypot with Reactive-Adaptive Multi-Agent Intelligence
--
-- Part 1: Core schema (users, services, decoy files, sessions, events, environment)
-- Part 2: Telemetry pipeline additions (raw_events, session_events, extra indexes)
-- =============================================================================

-- Extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- =============================================================================
-- ENUM types
-- =============================================================================

CREATE TYPE deception_mode_enum AS ENUM (
    'baseline',
    'passive',
    'active',
    'aggressive',
    'reconstruction'
);

CREATE TYPE event_category_enum AS ENUM (
    'ssh',
    'http',
    'file_access',
    'auth',
    'network',
    'lateral_movement',
    'exfiltration',
    'deception_trigger',
    'system'
);

CREATE TYPE event_severity_enum AS ENUM (
    'info',
    'low',
    'medium',
    'high',
    'critical'
);

CREATE TYPE service_status_enum AS ENUM (
    'running',
    'stopped',
    'degraded',
    'honeypot',
    'decoy'
);

CREATE TYPE user_role_enum AS ENUM (
    'admin',
    'developer',
    'finance',
    'hr',
    'it_support',
    'intern',
    'management',
    'system'
);

-- =============================================================================
-- TABLE: users
-- Fake company users embedded in the deception environment.
-- =============================================================================
CREATE TABLE IF NOT EXISTS users (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username        VARCHAR(64)  NOT NULL UNIQUE,
    full_name       VARCHAR(128) NOT NULL,
    email           VARCHAR(256) NOT NULL UNIQUE,
    department      VARCHAR(64)  NOT NULL,
    role            user_role_enum NOT NULL DEFAULT 'intern',
    is_decoy        BOOLEAN NOT NULL DEFAULT TRUE,
    ssh_enabled     BOOLEAN NOT NULL DEFAULT FALSE,
    home_dir        VARCHAR(256),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata        JSONB NOT NULL DEFAULT '{}'::JSONB
);

-- =============================================================================
-- TABLE: services
-- Tracks all running deception and real services in the environment.
-- =============================================================================
CREATE TABLE IF NOT EXISTS services (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name            VARCHAR(128) NOT NULL UNIQUE,
    description     TEXT,
    status          service_status_enum NOT NULL DEFAULT 'running',
    host            VARCHAR(256) NOT NULL,
    port            INTEGER,
    protocol        VARCHAR(32),
    is_honeypot     BOOLEAN NOT NULL DEFAULT FALSE,
    is_decoy        BOOLEAN NOT NULL DEFAULT FALSE,
    network         VARCHAR(64),
    docker_name     VARCHAR(128),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata        JSONB NOT NULL DEFAULT '{}'::JSONB
);

-- =============================================================================
-- TABLE: decoy_files
-- All decoy/bait files deployed in the deception environment.
-- The file server and orchestrator manage these via the API.
-- =============================================================================
CREATE TABLE IF NOT EXISTS decoy_files (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    filename        VARCHAR(512) NOT NULL,
    filepath        TEXT NOT NULL,
    content_type    VARCHAR(128),
    size_bytes      BIGINT DEFAULT 0,
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    bait_level      INTEGER NOT NULL DEFAULT 1  CHECK (bait_level BETWEEN 1 AND 5),
    access_count    INTEGER NOT NULL DEFAULT 0,
    last_accessed   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata        JSONB NOT NULL DEFAULT '{}'::JSONB
);

-- =============================================================================
-- TABLE: attack_sessions
-- Represents a single attacker interaction session (SSH, HTTP, etc.).
-- =============================================================================
CREATE TABLE IF NOT EXISTS attack_sessions (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id      VARCHAR(256) NOT NULL UNIQUE,   -- Cowrie / app session ID
    source_ip       INET NOT NULL,
    source_port     INTEGER,
    destination_ip  INET,
    destination_port INTEGER,
    protocol        VARCHAR(32) NOT NULL DEFAULT 'ssh',
    start_time      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    end_time        TIMESTAMPTZ,
    duration_secs   NUMERIC(10,3),
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    -- Populated by AI/ML agents in Part 2
    attacker_profile_id UUID REFERENCES attacker_profiles(id) ON DELETE SET NULL,
    threat_score    NUMERIC(5,2),
    intent          VARCHAR(128),
    metadata        JSONB NOT NULL DEFAULT '{}'::JSONB
);

-- =============================================================================
-- TABLE: events
-- Normalized telemetry events from all deception surfaces.
-- =============================================================================
CREATE TABLE IF NOT EXISTS events (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id      UUID REFERENCES attack_sessions(id) ON DELETE SET NULL,
    event_time      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source          VARCHAR(128) NOT NULL,           -- 'cowrie', 'web', 'fileserver'
    category        event_category_enum NOT NULL,
    severity        event_severity_enum NOT NULL DEFAULT 'info',
    event_type      VARCHAR(128) NOT NULL,           -- e.g. 'ssh.login.attempt'
    source_ip       INET,
    raw_data        JSONB NOT NULL DEFAULT '{}'::JSONB,
    normalized_data JSONB NOT NULL DEFAULT '{}'::JSONB,
    -- Fields populated by AI agents (Part 2)
    analyzed        BOOLEAN NOT NULL DEFAULT FALSE,
    analysis_result JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- TABLE: attacker_profiles
-- AI/ML-generated attacker profiles (skeleton for Part 2).
-- =============================================================================
CREATE TABLE IF NOT EXISTS attacker_profiles (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    source_ip       INET NOT NULL UNIQUE,
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    session_count   INTEGER NOT NULL DEFAULT 0,
    -- Populated by AI/ML agents in Part 2
    ttps            JSONB NOT NULL DEFAULT '[]'::JSONB,  -- MITRE ATT&CK TTPs
    skill_level     VARCHAR(32),
    likely_intent   VARCHAR(128),
    threat_score    NUMERIC(5,2) DEFAULT 0,
    profile_data    JSONB NOT NULL DEFAULT '{}'::JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- TABLE: environment_state
-- Centralized record of the current deception environment configuration.
-- =============================================================================
CREATE TABLE IF NOT EXISTS environment_state (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    snapshot_time   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deception_mode  deception_mode_enum NOT NULL DEFAULT 'baseline',
    is_current      BOOLEAN NOT NULL DEFAULT FALSE,
    state           JSONB NOT NULL DEFAULT '{}'::JSONB,
    applied_by      VARCHAR(128) DEFAULT 'system',
    notes           TEXT
);

-- =============================================================================
-- TABLE: deception_actions
-- Log of all deception actions applied by the orchestrator (Part 2 populates).
-- =============================================================================
CREATE TABLE IF NOT EXISTS deception_actions (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    action_time     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    action_type     VARCHAR(128) NOT NULL,   -- e.g. 'add_decoy_file', 'change_mode'
    trigger_event   UUID REFERENCES events(id) ON DELETE SET NULL,
    trigger_session UUID REFERENCES attack_sessions(id) ON DELETE SET NULL,
    parameters      JSONB NOT NULL DEFAULT '{}'::JSONB,
    result          JSONB,
    success         BOOLEAN,
    applied_by      VARCHAR(128) DEFAULT 'system',
    notes           TEXT
);

-- =============================================================================
-- Part 2: raw_events — Immutable forensic copy of every raw log line
--   Separate from events table: never modified, never analyzed, never deleted.
-- =============================================================================
CREATE TABLE IF NOT EXISTS raw_events (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    received_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source          VARCHAR(128) NOT NULL,           -- 'cowrie', 'web', 'fileserver', 'network'
    raw_data        JSONB NOT NULL DEFAULT '{}'::JSONB,
    canonical_event_id UUID REFERENCES events(id) ON DELETE SET NULL,
    -- Forensic integrity: record the SHA-256 of raw_data at write time
    data_hash       VARCHAR(64)
);

-- =============================================================================
-- Part 2: session_events — Junction table linking sessions ↔ events explicitly
--   Provides fast lookup of all events for a session without full table scan.
-- =============================================================================
CREATE TABLE IF NOT EXISTS session_events (
    session_id      UUID NOT NULL REFERENCES attack_sessions(id) ON DELETE CASCADE,
    event_id        UUID NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    event_time      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (session_id, event_id)
);

-- =============================================================================
-- Indexes for performance (Part 1 + Part 2)
-- =============================================================================
CREATE INDEX IF NOT EXISTS idx_events_session       ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_time          ON events(event_time DESC);
CREATE INDEX IF NOT EXISTS idx_events_source_ip     ON events(source_ip);
CREATE INDEX IF NOT EXISTS idx_events_category      ON events(category);
CREATE INDEX IF NOT EXISTS idx_events_event_type    ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_analyzed      ON events(analyzed) WHERE analyzed = FALSE;
CREATE INDEX IF NOT EXISTS idx_sessions_ip          ON attack_sessions(source_ip);
CREATE INDEX IF NOT EXISTS idx_sessions_active      ON attack_sessions(is_active) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_decoy_files_active   ON decoy_files(is_active) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_env_state_current    ON environment_state(is_current) WHERE is_current = TRUE;
CREATE INDEX IF NOT EXISTS idx_raw_events_source    ON raw_events(source);
CREATE INDEX IF NOT EXISTS idx_raw_events_time      ON raw_events(received_at DESC);
CREATE INDEX IF NOT EXISTS idx_session_events_sess  ON session_events(session_id);
CREATE INDEX IF NOT EXISTS idx_session_events_evt   ON session_events(event_id);

-- =============================================================================
-- Updated_at trigger function
-- =============================================================================
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER services_updated_at
    BEFORE UPDATE ON services
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER decoy_files_updated_at
    BEFORE UPDATE ON decoy_files
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER attacker_profiles_updated_at
    BEFORE UPDATE ON attacker_profiles
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- Done
