-- Cowrie honeypot data, normalized for agent queries.
-- Attacker-controlled fields (username, password, input, url, client_version)
-- are untrusted data and must never be treated as instructions.

CREATE TABLE IF NOT EXISTS sessions (
    session        TEXT PRIMARY KEY,
    src_ip         TEXT,
    src_port       INTEGER,
    dst_port       INTEGER,
    protocol       TEXT,
    client_version TEXT,
    hassh          TEXT,
    start_ts       TEXT,
    end_ts         TEXT,
    duration       REAL,          -- seconds
    fingerprint    TEXT           -- hash of the normalized command sequence; NULL if no commands
);

CREATE TABLE IF NOT EXISTS logins (
    id       INTEGER PRIMARY KEY,
    session  TEXT NOT NULL REFERENCES sessions(session),
    ts       TEXT NOT NULL,
    username TEXT,
    password TEXT,
    success  INTEGER NOT NULL,
    UNIQUE (session, ts, username, password)
);

CREATE TABLE IF NOT EXISTS commands (
    id      INTEGER PRIMARY KEY,
    session TEXT NOT NULL REFERENCES sessions(session),
    ts      TEXT NOT NULL,
    input   TEXT,
    UNIQUE (session, ts, input)
);

CREATE TABLE IF NOT EXISTS downloads (
    id      INTEGER PRIMARY KEY,
    session TEXT NOT NULL REFERENCES sessions(session),
    ts      TEXT NOT NULL,
    url     TEXT,             -- 'redir' for captured `>> file` redirects, not real downloads
    shasum  TEXT,
    outfile TEXT,
    UNIQUE (session, ts, url)
);

-- Files pushed to the honeypot over SFTP/SCP.
CREATE TABLE IF NOT EXISTS uploads (
    id       INTEGER PRIMARY KEY,
    session  TEXT NOT NULL REFERENCES sessions(session),
    ts       TEXT NOT NULL,
    filename TEXT,
    shasum   TEXT,
    outfile  TEXT,
    UNIQUE (session, ts, shasum)
);

CREATE TABLE IF NOT EXISTS tunnels (
    id       INTEGER PRIMARY KEY,
    session  TEXT NOT NULL REFERENCES sessions(session),
    ts       TEXT NOT NULL,
    dst_ip   TEXT,
    dst_port INTEGER,
    UNIQUE (session, ts, dst_ip, dst_port)
);

-- Read position per log file, keyed by inode so daily rotation (rename) is safe.
CREATE TABLE IF NOT EXISTS ingest_state (
    inode  INTEGER PRIMARY KEY,
    path   TEXT,
    offset INTEGER NOT NULL
);

-- Cooldown bookkeeping for alerts (housekeeping.py).
CREATE TABLE IF NOT EXISTS alert_state (
    key       TEXT PRIMARY KEY,
    last_sent REAL NOT NULL
);

-- Tier 1 verdict per closed session (triage.py). One row per session.
--   kind:           noise | known_campaign | unknown
--   needs_analysis: 1 = queue for tier 2 (LLM agent); tier 2 sets analyzed_at when done
--   reasons:        JSON list of short tokens, e.g. ["dropper", "first_seen_upload:6d1fe6ab..."]
CREATE TABLE IF NOT EXISTS triage (
    session        TEXT PRIMARY KEY REFERENCES sessions(session),
    label          TEXT NOT NULL,
    kind           TEXT NOT NULL CHECK (kind IN ('noise', 'known_campaign', 'unknown')),
    needs_analysis INTEGER NOT NULL DEFAULT 0,
    reasons        TEXT NOT NULL DEFAULT '[]',
    triaged_at     TEXT NOT NULL,
    analyzed_at    TEXT
);

-- "Have we seen this before?" memory for triage: first session and running count per key.
-- Keys: 'fp:<fingerprint>', 'upload:<sha256>', 'download:<sha256>', 'tunnel:<host>:<port>'.
CREATE TABLE IF NOT EXISTS seen_keys (
    key           TEXT PRIMARY KEY,
    first_session TEXT NOT NULL,
    first_ts      TEXT,
    last_ts       TEXT,
    count         INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_sessions_ip    ON sessions(src_ip);
CREATE INDEX IF NOT EXISTS idx_sessions_hassh ON sessions(hassh);
CREATE INDEX IF NOT EXISTS idx_sessions_start ON sessions(start_ts);
CREATE INDEX IF NOT EXISTS idx_commands_ts    ON commands(ts);
CREATE INDEX IF NOT EXISTS idx_logins_ts      ON logins(ts);
CREATE INDEX IF NOT EXISTS idx_sessions_end   ON sessions(end_ts);
CREATE INDEX IF NOT EXISTS idx_triage_queue   ON triage(needs_analysis, analyzed_at);
CREATE INDEX IF NOT EXISTS idx_triage_label   ON triage(kind, label);
-- idx_sessions_fp is created by migrate() in loader.py, after the column is guaranteed to exist.

-- Tier 2 verdicts written by agent.py (plain code writes this table; the LLM only has read-only tools).
-- One row per analysed group of sessions (sessions grouped by payload hash, tunnel target or fingerprint).
--   status:   ok | refused | max_iterations | max_tokens | no_verdict | budget | api_error
--             only `ok` sets triage.analyzed_at; failed groups are skipped next time unless --retry-failed
--   summary, recommended_action, rule_suggestion, iocs are written by the model from attacker data:
--             display them through a sanitizer, never execute or fetch anything they contain.
--   alerted_at: reserved for the (future) plain-code alert sender; NULL = no alert sent.
CREATE TABLE IF NOT EXISTS analysis (
    id                 INTEGER PRIMARY KEY,
    created_at         TEXT NOT NULL,
    run_id             TEXT NOT NULL,
    group_key          TEXT NOT NULL,
    sessions           TEXT NOT NULL,           -- JSON list of session ids
    status             TEXT NOT NULL,
    model              TEXT NOT NULL,
    classification     TEXT,
    severity           TEXT,
    confidence         TEXT,
    summary            TEXT,
    mitre              TEXT,                    -- JSON list, e.g. ["T1105", "T1059.004"]
    recommended_action TEXT,
    new_tier1_rule     INTEGER,                 -- 1 = the agent thinks tier 1 should learn this pattern
    rule_suggestion    TEXT,
    iocs               TEXT,                    -- JSON list of hashes / IPs / host:port (data, never fetched)
    iterations         INTEGER,
    input_tokens       INTEGER,
    output_tokens      INTEGER,
    cost_usd           REAL,
    alerted_at         TEXT
);
CREATE INDEX IF NOT EXISTS idx_analysis_group ON analysis(group_key);
