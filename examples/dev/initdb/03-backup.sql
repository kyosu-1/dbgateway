-- Schema for backups of approved writes (databases[].backup).
-- The write user creates one table per backed-up write; the read user has
-- no access (backup tables are only a source for restores).
CREATE SCHEMA dbgw_backup;
GRANT USAGE, CREATE ON SCHEMA dbgw_backup TO dbgw_writer;
