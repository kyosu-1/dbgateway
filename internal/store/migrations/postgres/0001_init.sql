-- PostgreSQL schema of the management database. Same versions, tables and
-- columns as the SQLite migrations in the parent directory, with native
-- types: times are timestamptz (written in UTC, millisecond precision),
-- lists and documents are jsonb.
-- Secret values are never stored: *_hash columns hold hex SHA-256.

CREATE TABLE users (
    email         text PRIMARY KEY,
    idp_groups    jsonb NOT NULL DEFAULT '[]',
    created_at    timestamptz NOT NULL,
    last_login_at timestamptz NOT NULL
);

CREATE TABLE sessions (
    id_hash    text PRIMARY KEY,
    email      text NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL
);
CREATE INDEX sessions_expires_at ON sessions (expires_at);

CREATE TABLE oauth_clients (
    client_id     text PRIMARY KEY,
    client_name   text NOT NULL,
    redirect_uris jsonb NOT NULL,
    created_at    timestamptz NOT NULL
);

CREATE TABLE auth_codes (
    code_hash      text PRIMARY KEY,
    client_id      text NOT NULL,
    client_name    text NOT NULL,
    redirect_uri   text NOT NULL,
    code_challenge text NOT NULL,
    scopes         jsonb NOT NULL,
    resource       text NOT NULL,
    email          text NOT NULL,
    agent_name     text NOT NULL,
    databases      jsonb NOT NULL,
    family_id      text NOT NULL,
    created_at     timestamptz NOT NULL,
    expires_at     timestamptz NOT NULL,
    used_at        timestamptz
);
CREATE INDEX auth_codes_expires_at ON auth_codes (expires_at);

CREATE TABLE device_codes (
    device_code_hash text PRIMARY KEY,
    user_code_hash   text NOT NULL UNIQUE,
    client_id        text NOT NULL,
    scopes           jsonb NOT NULL,
    status           text NOT NULL,
    email            text NOT NULL DEFAULT '',
    interval_ms      bigint NOT NULL,
    last_polled_at   timestamptz,
    created_at       timestamptz NOT NULL,
    expires_at       timestamptz NOT NULL
);
CREATE INDEX device_codes_expires_at ON device_codes (expires_at);

CREATE TABLE tokens (
    id          text PRIMARY KEY,
    hash        text NOT NULL UNIQUE,
    type        text NOT NULL,
    kind        text NOT NULL,
    human       text NOT NULL,
    agent       text NOT NULL DEFAULT '',
    client_id   text NOT NULL,
    client_name text NOT NULL DEFAULT '',
    scopes      jsonb NOT NULL,
    databases   jsonb NOT NULL,
    audience    text NOT NULL,
    family_id   text NOT NULL DEFAULT '',
    parent_id   text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL,
    expires_at  timestamptz NOT NULL,
    used_at     timestamptz,
    revoked_at  timestamptz
);
CREATE INDEX tokens_human ON tokens (human);
CREATE INDEX tokens_family_id ON tokens (family_id);
CREATE INDEX tokens_parent_id ON tokens (parent_id);
CREATE INDEX tokens_expires_at ON tokens (expires_at);
