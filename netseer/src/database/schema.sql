-- NetSeer database schema (PROTOTYPE-BRIEF §5). SQLite, WAL mode (set in db.py).
-- Timestamps are ISO-8601 strings in UTC unless noted.

CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY,
    username    TEXT NOT NULL UNIQUE,
    pw_hash     TEXT NOT NULL,
    role        TEXT NOT NULL CHECK (role IN ('admin', 'user')),
    theme       TEXT NOT NULL DEFAULT 'white',
    created_at  TEXT NOT NULL
);
-- Enforces 1 admin + at most 1 user (CONCEPTS A12).
CREATE UNIQUE INDEX IF NOT EXISTS one_per_role ON users(role);

CREATE TABLE IF NOT EXISTS login_attempts (
    username  TEXT NOT NULL,
    ts        TEXT NOT NULL,
    success   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_login_attempts_user ON login_attempts(username, ts);

CREATE TABLE IF NOT EXISTS sessions (
    token       TEXT PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf        TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    expires_at  TEXT            -- 10 minutes from sign-in; only the Extend button moves it
);

CREATE TABLE IF NOT EXISTS audit_log (
    id       INTEGER PRIMARY KEY,
    ts       TEXT NOT NULL,
    user_id  INTEGER,
    action   TEXT NOT NULL,
    detail   TEXT,
    ip       TEXT,          -- client IP (account events)
    mac      TEXT           -- client MAC from the neighbour table; NULL = unknown
);
CREATE INDEX IF NOT EXISTS idx_audit_log_ts ON audit_log(ts);

-- Overrides config/netseer.toml; value is JSON.
CREATE TABLE IF NOT EXISTS settings (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);

-- Fernet-encrypted (abuseipdb, virustotal, cloud_llm).
CREATE TABLE IF NOT EXISTS api_keys (
    name        TEXT PRIMARY KEY,
    ciphertext  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS analyses (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL,
    mode        TEXT NOT NULL CHECK (mode IN ('offline', 'live')),
    status      TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    started_at  TEXT,
    stopped_at  TEXT,
    mirror_if   TEXT,
    lan_if      TEXT,
    eve_offset  INTEGER NOT NULL DEFAULT 0,
    n_events    INTEGER NOT NULL DEFAULT 0,
    n_alerts    INTEGER NOT NULL DEFAULT 0,
    error       TEXT,
    note        TEXT            -- administrator's note
);

CREATE TABLE IF NOT EXISTS analysis_files (
    analysis_id  INTEGER NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    filename     TEXT NOT NULL,
    sha256       TEXT NOT NULL,
    size         INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_analysis_files_analysis ON analysis_files(analysis_id);

CREATE TABLE IF NOT EXISTS alerts (
    id               INTEGER PRIMARY KEY,
    analysis_id      INTEGER NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    ts               TEXT NOT NULL,
    flow_id          INTEGER,
    src_ip           TEXT,
    src_port         INTEGER,
    dest_ip          TEXT,
    dest_port        INTEGER,
    proto            TEXT,
    app_proto        TEXT,
    sid              INTEGER,
    signature        TEXT,
    category         TEXT,
    classtype        TEXT,
    priority         INTEGER,
    sig_severity     TEXT,
    mitre_tactic     TEXT,
    mitre_technique  TEXT,
    direction        TEXT,
    raw_json         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_analysis ON alerts(analysis_id, ts);

CREATE TABLE IF NOT EXISTS devices (
    id             INTEGER PRIMARY KEY,
    analysis_id    INTEGER NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    ip             TEXT NOT NULL,
    mac            TEXT,
    vendor         TEXT,
    hostname       TEXT,
    services_json  TEXT,
    first_seen     TEXT,
    last_seen      TEXT,
    type           TEXT NOT NULL DEFAULT 'unknown',
    criticality    REAL NOT NULL DEFAULT 5,
    risk           REAL NOT NULL DEFAULT 0,
    attributed     INTEGER NOT NULL DEFAULT 0,
    UNIQUE (analysis_id, ip)
);
CREATE INDEX IF NOT EXISTS idx_devices_analysis ON devices(analysis_id);

CREATE TABLE IF NOT EXISTS alert_groups (
    id              INTEGER PRIMARY KEY,
    analysis_id     INTEGER NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    src_ip          TEXT,
    dest_ip         TEXT,
    sid             INTEGER,
    signature       TEXT,
    classtype       TEXT,
    proto           TEXT,
    dest_port       INTEGER,
    first_seen      TEXT,
    last_seen       TEXT,
    count           INTEGER NOT NULL,
    max_priority    INTEGER,
    rep_alert_id    INTEGER,
    alert_ids_json  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alert_groups_analysis ON alert_groups(analysis_id);

CREATE TABLE IF NOT EXISTS incidents (
    id             INTEGER PRIMARY KEY,
    analysis_id    INTEGER NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    title          TEXT NOT NULL,
    rule           TEXT NOT NULL,
    src_ips_json   TEXT NOT NULL,
    dest_ips_json  TEXT NOT NULL,
    first_seen     TEXT,
    last_seen      TEXT,
    n_alerts       INTEGER NOT NULL,
    likelihood     REAL,
    impact         REAL,
    band           TEXT,
    score          REAL,
    factors_json   TEXT,
    evidence_json  TEXT
);
CREATE INDEX IF NOT EXISTS idx_incidents_analysis ON incidents(analysis_id);

CREATE TABLE IF NOT EXISTS incident_groups (
    incident_id  INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    group_id     INTEGER NOT NULL REFERENCES alert_groups(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_incident_groups_incident ON incident_groups(incident_id);

CREATE TABLE IF NOT EXISTS interpretations (
    id                 INTEGER PRIMARY KEY,
    incident_id        INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    intent             TEXT NOT NULL,
    model              TEXT NOT NULL,
    evidence_hash      TEXT NOT NULL,
    output_json        TEXT,
    verification_json  TEXT,
    created_at         TEXT NOT NULL,
    latency_s          REAL
);
CREATE INDEX IF NOT EXISTS idx_interpretations_incident ON interpretations(incident_id, intent, evidence_hash);

CREATE TABLE IF NOT EXISTS packet_stats (
    analysis_id  INTEGER NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    minute       TEXT NOT NULL,      -- YYYY-MM-DDTHH:MM (UTC); flows are spread over their duration
    packets      INTEGER NOT NULL DEFAULT 0,
    bytes        INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (analysis_id, minute)
);

-- Every IP outside the LAN CIDRs seen in an analysis (Devices → External sources).
CREATE TABLE IF NOT EXISTS external_hosts (
    id           INTEGER PRIMARY KEY,
    analysis_id  INTEGER NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    ip           TEXT NOT NULL,
    hostname     TEXT,
    direction    TEXT,               -- inbound | outbound | both
    first_seen   TEXT,
    last_seen    TEXT,
    n_flows      INTEGER NOT NULL DEFAULT 0,
    n_alerts     INTEGER NOT NULL DEFAULT 0,
    bytes        INTEGER NOT NULL DEFAULT 0,
    ports_json   TEXT,
    peers_json   TEXT,
    UNIQUE (analysis_id, ip)
);
CREATE INDEX IF NOT EXISTS idx_external_hosts_analysis ON external_hosts(analysis_id);

CREATE TABLE IF NOT EXISTS ti_cache (
    indicator    TEXT PRIMARY KEY,
    source       TEXT NOT NULL,
    result_json  TEXT NOT NULL,
    fetched_at   TEXT NOT NULL
);

-- Names seen for IPs in any analysis (DNS answers, TLS SNI, HTTP host, DHCP); kept until Detonate (CONCEPTS A3).
CREATE TABLE IF NOT EXISTS ip_names (
    ip          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

-- Findings about an analysis (CONCEPTS A16 capture checks, A17 networks), shown as Info.
CREATE TABLE IF NOT EXISTS analysis_info (
    id           INTEGER PRIMARY KEY,
    analysis_id  INTEGER NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    kind         TEXT NOT NULL,      -- capture | network
    level        TEXT NOT NULL CHECK (level IN ('info', 'warning')),
    title        TEXT NOT NULL,
    detail_json  TEXT,
    created_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_analysis_info_analysis ON analysis_info(analysis_id, kind);

-- Observed communication between two hosts (a < b), for the Devices network map (A17).
CREATE TABLE IF NOT EXISTS host_links (
    analysis_id  INTEGER NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    a            TEXT NOT NULL,
    b            TEXT NOT NULL,
    flows        INTEGER NOT NULL DEFAULT 0,
    bytes        INTEGER NOT NULL DEFAULT 0,
    alerts       INTEGER NOT NULL DEFAULT 0,
    first_seen   TEXT,
    last_seen    TEXT,
    PRIMARY KEY (analysis_id, a, b)
);
