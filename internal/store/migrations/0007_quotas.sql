-- Quota usage (see internal/gateway/quota.go and docs/quotas.md).

-- Queries run and rows returned per requester (lower-cased e-mail of the
-- person, or "client:<id>") and quota, in one-minute buckets. Removed at
-- expires_at, when no window of the quota needs the bucket any more.
CREATE TABLE quota_usage (
    requester   TEXT NOT NULL,
    quota       TEXT NOT NULL,
    bucket      INTEGER NOT NULL,
    query_count INTEGER NOT NULL,
    row_count   INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    PRIMARY KEY (requester, quota, bucket)
);
CREATE INDEX quota_usage_expires ON quota_usage (expires_at);
