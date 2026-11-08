-- Write user used by dbgateway to run approved writes (phase 2).
-- No DDL privileges: schema changes never go through dbgateway.
CREATE ROLE dbgw_writer LOGIN PASSWORD 'writer';
GRANT CONNECT ON DATABASE app TO dbgw_writer;
GRANT USAGE ON SCHEMA public TO dbgw_writer;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO dbgw_writer;
