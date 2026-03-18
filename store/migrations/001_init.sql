CREATE TABLE IF NOT EXISTS grants (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL DEFAULT 'active',
    lane TEXT NOT NULL,
    tool_family TEXT NOT NULL,
    logical_action TEXT NOT NULL DEFAULT '',
    target TEXT NOT NULL DEFAULT '',
    scope TEXT NOT NULL DEFAULT '',
    session_id TEXT NOT NULL,
    runner_id TEXT NOT NULL,
    turn_id TEXT NOT NULL DEFAULT '',
    workload_key TEXT NOT NULL DEFAULT '',
    actor_user TEXT NOT NULL DEFAULT '',
    actor_virtual_identity TEXT NOT NULL DEFAULT '',
    actor_agent_id TEXT NOT NULL DEFAULT '',
    reason_code TEXT NOT NULL DEFAULT '',
    implementation_state TEXT NOT NULL DEFAULT '',
    credential_ref TEXT NOT NULL DEFAULT '',
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_grants_runner_id ON grants(runner_id);
CREATE INDEX IF NOT EXISTS idx_grants_session_id ON grants(session_id);
CREATE INDEX IF NOT EXISTS idx_grants_status ON grants(status);

CREATE TABLE IF NOT EXISTS credential_records (
    id TEXT PRIMARY KEY,
    credential_type TEXT NOT NULL,
    credential_value TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
