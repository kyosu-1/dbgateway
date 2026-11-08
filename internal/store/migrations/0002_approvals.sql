-- Approval requests and break-glass grants (phase 2).
-- Times are unix milliseconds. *_json columns hold JSON documents owned by
-- the approval package.

CREATE TABLE approval_requests (
    id                  TEXT PRIMARY KEY,
    requester_kind      TEXT NOT NULL,
    requester_human     TEXT NOT NULL,
    requester_agent     TEXT NOT NULL DEFAULT '',
    requester_client_id TEXT NOT NULL DEFAULT '',
    database_name       TEXT NOT NULL,
    raw_sql             TEXT NOT NULL,
    normalized_sql      TEXT NOT NULL,
    reason              TEXT NOT NULL,
    analysis_json       TEXT NOT NULL DEFAULT '{}',
    estimate_rows       REAL NOT NULL DEFAULT 0,
    max_affected_rows   INTEGER NOT NULL,
    risk                TEXT NOT NULL,
    approval_rule       TEXT NOT NULL,
    steps_json          TEXT NOT NULL,
    approvals_json      TEXT NOT NULL DEFAULT '[]',
    config_version      TEXT NOT NULL,
    binding_hash        TEXT NOT NULL,
    status              TEXT NOT NULL,
    version             INTEGER NOT NULL DEFAULT 0,
    created_at          INTEGER NOT NULL,
    expires_at          INTEGER NOT NULL,
    decided_at          INTEGER,
    decided_by          TEXT NOT NULL DEFAULT '',
    decision_comment    TEXT NOT NULL DEFAULT '',
    started_at          INTEGER,
    finished_at         INTEGER,
    result_json         TEXT NOT NULL DEFAULT ''
);
CREATE INDEX approval_requests_requester ON approval_requests (requester_human, created_at);
CREATE INDEX approval_requests_status ON approval_requests (status, expires_at);
CREATE INDEX approval_requests_created_at ON approval_requests (created_at);

CREATE TABLE break_glass_grants (
    id             TEXT PRIMARY KEY,
    human          TEXT NOT NULL,
    databases      TEXT NOT NULL,
    reason         TEXT NOT NULL,
    step_up_method TEXT NOT NULL DEFAULT '',
    created_at     INTEGER NOT NULL,
    expires_at     INTEGER NOT NULL
);
CREATE INDEX break_glass_grants_human ON break_glass_grants (human, expires_at);
