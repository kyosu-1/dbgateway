-- Web SQL editor (see internal/web/console*.go and docs/console.md).

-- Statements a person ran in the editor, as typed. Visible only to that
-- person (every query filters by email) and removed at expires_at.
CREATE TABLE console_history (
    id            TEXT PRIMARY KEY,
    email         TEXT NOT NULL,
    database_name TEXT NOT NULL,
    sql_text      TEXT NOT NULL,
    reason        TEXT NOT NULL,
    status        TEXT NOT NULL,
    row_count     INTEGER,
    request_id    TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL
);
CREATE INDEX console_history_email ON console_history (email, created_at);

-- Queries a person saved by name (SQL and database only, never results).
CREATE TABLE console_saved_queries (
    id            TEXT PRIMARY KEY,
    email         TEXT NOT NULL,
    name          TEXT NOT NULL,
    database_name TEXT NOT NULL,
    sql_text      TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL
);
CREATE INDEX console_saved_queries_email ON console_saved_queries (email, name);
