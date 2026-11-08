-- Web UI: step-up authentication on browser sessions, passkeys (WebAuthn),
-- one-time passkey enrollment links and in-flight WebAuthn ceremonies.
-- Times are unix milliseconds. Secrets are stored as hex SHA-256 only.

-- The last re-authentication of the session (passkey, IdP or dev).
ALTER TABLE sessions ADD COLUMN step_up_method TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN step_up_at INTEGER;

-- A registered passkey. id is the base64url credential ID. user_handle is
-- the random WebAuthn user handle shared by every passkey of one person.
-- credential is the JSON credential record owned by the auth package.
CREATE TABLE passkeys (
    id           TEXT PRIMARY KEY,
    email        TEXT NOT NULL,
    user_handle  BLOB NOT NULL,
    name         TEXT NOT NULL,
    credential   TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER
);
CREATE INDEX passkeys_email ON passkeys (email);

-- A one-time link created by `dbgw passkey enroll`.
CREATE TABLE passkey_enrollments (
    token_hash TEXT PRIMARY KEY,
    email      TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at    INTEGER
);
CREATE INDEX passkey_enrollments_expires_at ON passkey_enrollments (expires_at);

-- A WebAuthn ceremony between its begin and finish requests. id_hash is the
-- hash of the random ID kept in the browser cookie; data is the library's
-- session data (challenge, allowed credentials). Rows are single-use.
CREATE TABLE webauthn_sessions (
    id_hash    TEXT PRIMARY KEY,
    purpose    TEXT NOT NULL,
    email      TEXT NOT NULL DEFAULT '',
    data       TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX webauthn_sessions_expires_at ON webauthn_sessions (expires_at);
