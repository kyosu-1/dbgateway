-- Approval requests and break-glass grants (phase 2).
-- *_json columns hold JSON documents owned by the approval package.
-- result_json is NULL until the execution has finished.

CREATE TABLE approval_requests (
    id                  text PRIMARY KEY,
    requester_kind      text NOT NULL,
    requester_human     text NOT NULL,
    requester_agent     text NOT NULL DEFAULT '',
    requester_client_id text NOT NULL DEFAULT '',
    database_name       text NOT NULL,
    raw_sql             text NOT NULL,
    normalized_sql      text NOT NULL,
    reason              text NOT NULL,
    analysis_json       jsonb NOT NULL DEFAULT '{}',
    estimate_rows       double precision NOT NULL DEFAULT 0,
    max_affected_rows   bigint NOT NULL,
    risk                text NOT NULL,
    approval_rule       text NOT NULL,
    steps_json          jsonb NOT NULL,
    approvals_json      jsonb NOT NULL DEFAULT '[]',
    config_version      text NOT NULL,
    binding_hash        text NOT NULL,
    status              text NOT NULL,
    version             bigint NOT NULL DEFAULT 0,
    created_at          timestamptz NOT NULL,
    expires_at          timestamptz NOT NULL,
    decided_at          timestamptz,
    decided_by          text NOT NULL DEFAULT '',
    decision_comment    text NOT NULL DEFAULT '',
    started_at          timestamptz,
    finished_at         timestamptz,
    result_json         jsonb
);
CREATE INDEX approval_requests_requester ON approval_requests (requester_human, created_at);
CREATE INDEX approval_requests_status ON approval_requests (status, expires_at);
CREATE INDEX approval_requests_created_at ON approval_requests (created_at);

CREATE TABLE break_glass_grants (
    id             text PRIMARY KEY,
    human          text NOT NULL,
    databases      jsonb NOT NULL,
    reason         text NOT NULL,
    step_up_method text NOT NULL DEFAULT '',
    created_at     timestamptz NOT NULL,
    expires_at     timestamptz NOT NULL
);
CREATE INDEX break_glass_grants_human ON break_glass_grants (human, expires_at);
