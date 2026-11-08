-- Web SQL editor. PostgreSQL version of migrations/0006_console.sql.

-- Statements a person ran in the editor, as typed (visible only to them).
CREATE TABLE console_history (
    id            text PRIMARY KEY,
    email         text NOT NULL,
    database_name text NOT NULL,
    sql_text      text NOT NULL,
    reason        text NOT NULL,
    status        text NOT NULL,
    row_count     bigint,
    request_id    text NOT NULL,
    created_at    timestamptz NOT NULL,
    expires_at    timestamptz NOT NULL
);
CREATE INDEX console_history_email ON console_history (email, created_at);

-- Queries a person saved by name (SQL and database only).
CREATE TABLE console_saved_queries (
    id            text PRIMARY KEY,
    email         text NOT NULL,
    name          text NOT NULL,
    database_name text NOT NULL,
    sql_text      text NOT NULL,
    created_at    timestamptz NOT NULL,
    updated_at    timestamptz NOT NULL
);
CREATE INDEX console_saved_queries_email ON console_saved_queries (email, name);
