-- Times are unix milliseconds. Lists are JSON arrays.
-- Secret values are never stored: *_hash columns hold hex SHA-256.

CREATE TABLE users (
    email         TEXT PRIMARY KEY,
    idp_groups    TEXT NOT NULL DEFAULT '[]',
    created_at    INTEGER NOT NULL,
    last_login_at INTEGER NOT NULL
);

CREATE TABLE sessions (
    id_hash    TEXT PRIMARY KEY,
    email      TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX sessions_expires_at ON sessions (expires_at);

CREATE TABLE oauth_clients (
    client_id     TEXT PRIMARY KEY,
    client_name   TEXT NOT NULL,
    redirect_uris TEXT NOT NULL,
    created_at    INTEGER NOT NULL
);

CREATE TABLE auth_codes (
    code_hash      TEXT PRIMARY KEY,
    client_id      TEXT NOT NULL,
    client_name    TEXT NOT NULL,
    redirect_uri   TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    scopes         TEXT NOT NULL,
    resource       TEXT NOT NULL,
    email          TEXT NOT NULL,
    agent_name     TEXT NOT NULL,
    databases      TEXT NOT NULL,
    family_id      TEXT NOT NULL,
    created_at     INTEGER NOT NULL,
    expires_at     INTEGER NOT NULL,
    used_at        INTEGER
);
CREATE INDEX auth_codes_expires_at ON auth_codes (expires_at);

CREATE TABLE device_codes (
    device_code_hash TEXT PRIMARY KEY,
    user_code_hash   TEXT NOT NULL UNIQUE,
    client_id        TEXT NOT NULL,
    scopes           TEXT NOT NULL,
    status           TEXT NOT NULL,
    email            TEXT NOT NULL DEFAULT '',
    interval_ms      INTEGER NOT NULL,
    last_polled_at   INTEGER,
    created_at       INTEGER NOT NULL,
    expires_at       INTEGER NOT NULL
);
CREATE INDEX device_codes_expires_at ON device_codes (expires_at);

CREATE TABLE tokens (
    id          TEXT PRIMARY KEY,
    hash        TEXT NOT NULL UNIQUE,
    type        TEXT NOT NULL,
    kind        TEXT NOT NULL,
    human       TEXT NOT NULL,
    agent       TEXT NOT NULL DEFAULT '',
    client_id   TEXT NOT NULL,
    client_name TEXT NOT NULL DEFAULT '',
    scopes      TEXT NOT NULL,
    databases   TEXT NOT NULL,
    audience    TEXT NOT NULL,
    family_id   TEXT NOT NULL DEFAULT '',
    parent_id   TEXT NOT NULL DEFAULT '',
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    used_at     INTEGER,
    revoked_at  INTEGER
);
CREATE INDEX tokens_human ON tokens (human);
CREATE INDEX tokens_family_id ON tokens (family_id);
CREATE INDEX tokens_parent_id ON tokens (parent_id);
CREATE INDEX tokens_expires_at ON tokens (expires_at);
