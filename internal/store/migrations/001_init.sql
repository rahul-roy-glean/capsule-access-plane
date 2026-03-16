CREATE TABLE IF NOT EXISTS grants (
    id TEXT PRIMARY KEY,
    grant_type TEXT NOT NULL,
    status TEXT NOT NULL,
    session_id TEXT NOT NULL,
    runner_id TEXT NOT NULL,
    workload_key TEXT NOT NULL,
    turn_id TEXT NOT NULL DEFAULT '',
    actor_user TEXT NOT NULL DEFAULT '',
    virtual_identity TEXT NOT NULL DEFAULT '',
    agent_id TEXT NOT NULL DEFAULT '',
    target TEXT NOT NULL DEFAULT '',
    scope TEXT NOT NULL DEFAULT '',
    credential_ref TEXT NOT NULL DEFAULT '',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_grants_runner_id ON grants(runner_id);
CREATE INDEX IF NOT EXISTS idx_grants_status ON grants(status);
CREATE INDEX IF NOT EXISTS idx_grants_expires_at ON grants(expires_at);

CREATE TABLE IF NOT EXISTS helper_sessions (
    id TEXT PRIMARY KEY,
    grant_id TEXT NOT NULL,
    tool_family TEXT NOT NULL,
    format TEXT NOT NULL DEFAULT '',
    env_json TEXT NOT NULL DEFAULT '{}',
    files_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(grant_id) REFERENCES grants(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_helper_sessions_grant_id ON helper_sessions(grant_id);

CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    session_id TEXT NOT NULL DEFAULT '',
    runner_id TEXT NOT NULL DEFAULT '',
    turn_id TEXT NOT NULL DEFAULT '',
    actor_user TEXT NOT NULL DEFAULT '',
    virtual_identity TEXT NOT NULL DEFAULT '',
    agent_id TEXT NOT NULL DEFAULT '',
    target TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL DEFAULT '',
    result TEXT NOT NULL DEFAULT '',
    policy_decision TEXT NOT NULL DEFAULT '',
    duration_ms INTEGER NOT NULL DEFAULT 0,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_audit_events_runner_id ON audit_events(runner_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_created_at ON audit_events(created_at);

CREATE TABLE IF NOT EXISTS credential_records (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TEXT NOT NULL DEFAULT ''
);
