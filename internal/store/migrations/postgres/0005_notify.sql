-- Notifications (see internal/notify and docs/notifications.md).
-- PostgreSQL version of migrations/0005_notify.sql.

-- A dbgateway user linked to a Slack user (one each way).
CREATE TABLE slack_links (
    email      text PRIMARY KEY,
    slack_user text NOT NULL UNIQUE,
    linked_at  timestamptz NOT NULL
);

-- One-time linking codes shown on the account page (SHA-256 only).
CREATE TABLE slack_link_codes (
    code_hash  text PRIMARY KEY,
    email      text NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL
);
CREATE INDEX slack_link_codes_email ON slack_link_codes (email);

-- The Slack message that started the thread of an approval request, per
-- channel. event_json holds the approval_requested event (no literals).
CREATE TABLE slack_threads (
    request_id text NOT NULL,
    channel    text NOT NULL,
    target     text NOT NULL,
    ts         text NOT NULL,
    event_json text NOT NULL,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (request_id, channel)
);

-- Small key/value state of the notifier.
CREATE TABLE notify_state (
    key        text PRIMARY KEY,
    value      text NOT NULL,
    updated_at timestamptz NOT NULL
);
