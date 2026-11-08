-- Web UI: step-up authentication on browser sessions, passkeys (WebAuthn),
-- one-time passkey enrollment links and in-flight WebAuthn ceremonies.
-- PostgreSQL version of migrations/0004_web.sql. Secrets are SHA-256 only.

ALTER TABLE sessions ADD COLUMN step_up_method text NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN step_up_at timestamptz;

CREATE TABLE passkeys (
    id           text PRIMARY KEY,
    email        text NOT NULL,
    user_handle  bytea NOT NULL,
    name         text NOT NULL,
    credential   text NOT NULL,
    created_at   timestamptz NOT NULL,
    last_used_at timestamptz
);
CREATE INDEX passkeys_email ON passkeys (email);

CREATE TABLE passkey_enrollments (
    token_hash text PRIMARY KEY,
    email      text NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at    timestamptz
);
CREATE INDEX passkey_enrollments_expires_at ON passkey_enrollments (expires_at);

CREATE TABLE webauthn_sessions (
    id_hash    text PRIMARY KEY,
    purpose    text NOT NULL,
    email      text NOT NULL DEFAULT '',
    data       text NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL
);
CREATE INDEX webauthn_sessions_expires_at ON webauthn_sessions (expires_at);
