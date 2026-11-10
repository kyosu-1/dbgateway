-- Quota usage. PostgreSQL version of migrations/0007_quotas.sql.

-- Queries run and rows returned per requester and quota, in one-minute
-- buckets, shared by every instance. Removed at expires_at.
CREATE TABLE quota_usage (
    requester   text NOT NULL,
    quota       text NOT NULL,
    bucket      timestamptz NOT NULL,
    query_count bigint NOT NULL,
    row_count   bigint NOT NULL,
    expires_at  timestamptz NOT NULL,
    PRIMARY KEY (requester, quota, bucket)
);
CREATE INDEX quota_usage_expires ON quota_usage (expires_at);
