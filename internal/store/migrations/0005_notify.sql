-- Notifications (see internal/notify and docs/notifications.md).
-- Independent of the other migrations: applied by version, each once.

-- A dbgateway user linked to a Slack user (one each way).
CREATE TABLE slack_links (
    email      TEXT PRIMARY KEY,
    slack_user TEXT NOT NULL UNIQUE,
    linked_at  INTEGER NOT NULL
);

-- One-time linking codes shown on the account page. Only the SHA-256 of
-- the code is stored.
CREATE TABLE slack_link_codes (
    code_hash  TEXT PRIMARY KEY,
    email      TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX slack_link_codes_email ON slack_link_codes (email);

-- The Slack message that started the thread of an approval request, per
-- channel. target is the configured destination ("#name" or an ID).
-- event_json is the approval_requested event (normalized SQL only, no
-- literals), kept to re-render the message when the status changes.
CREATE TABLE slack_threads (
    request_id TEXT NOT NULL,
    channel    TEXT NOT NULL,
    target     TEXT NOT NULL,
    ts         TEXT NOT NULL,
    event_json TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (request_id, channel)
);

-- Small key/value state of the notifier (e.g. the configuration version
-- seen at the last start).
CREATE TABLE notify_state (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);
