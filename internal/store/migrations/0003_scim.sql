-- SCIM 2.0 provisioning (see internal/scim and docs/scim.md).
-- Independent of 0002: migrations are applied by version, each once.

-- A user provisioned by the IdP. email is the dbgateway identity (lower
-- case, matches users.email and tokens.human). Deleted users are kept as
-- tombstones (deleted_at set, active 0) so that they stay locked out.
CREATE TABLE scim_users (
    id             TEXT PRIMARY KEY,
    email          TEXT NOT NULL UNIQUE,
    user_name      TEXT NOT NULL UNIQUE COLLATE NOCASE,
    external_id    TEXT NOT NULL DEFAULT '',
    display_name   TEXT NOT NULL DEFAULT '',
    given_name     TEXT NOT NULL DEFAULT '',
    family_name    TEXT NOT NULL DEFAULT '',
    formatted_name TEXT NOT NULL DEFAULT '',
    emails         TEXT NOT NULL DEFAULT '[]',
    active         INTEGER NOT NULL DEFAULT 1,
    created_at     INTEGER NOT NULL,
    updated_at     INTEGER NOT NULL,
    deleted_at     INTEGER
);
CREATE INDEX scim_users_external_id ON scim_users (external_id);

CREATE TABLE scim_groups (
    id           TEXT PRIMARY KEY,
    display_name TEXT NOT NULL UNIQUE COLLATE NOCASE,
    external_id  TEXT NOT NULL DEFAULT '',
    created_at   INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL
);
CREATE INDEX scim_groups_external_id ON scim_groups (external_id);

CREATE TABLE scim_group_members (
    group_id TEXT NOT NULL REFERENCES scim_groups (id) ON DELETE CASCADE,
    user_id  TEXT NOT NULL REFERENCES scim_users (id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, user_id)
);
CREATE INDEX scim_group_members_user_id ON scim_group_members (user_id);
