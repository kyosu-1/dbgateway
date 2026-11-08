-- SCIM 2.0 provisioning (see internal/scim and docs/scim.md).
-- Where SQLite uses COLLATE NOCASE, PostgreSQL uses unique indexes on and
-- comparisons of lower(...).

-- A user provisioned by the IdP. email is the dbgateway identity (lower
-- case, matches users.email and tokens.human). Deleted users are kept as
-- tombstones (deleted_at set, active false) so that they stay locked out.
CREATE TABLE scim_users (
    id             text PRIMARY KEY,
    email          text NOT NULL UNIQUE,
    user_name      text NOT NULL,
    external_id    text NOT NULL DEFAULT '',
    display_name   text NOT NULL DEFAULT '',
    given_name     text NOT NULL DEFAULT '',
    family_name    text NOT NULL DEFAULT '',
    formatted_name text NOT NULL DEFAULT '',
    emails         jsonb NOT NULL DEFAULT '[]',
    active         boolean NOT NULL DEFAULT true,
    created_at     timestamptz NOT NULL,
    updated_at     timestamptz NOT NULL,
    deleted_at     timestamptz
);
CREATE UNIQUE INDEX scim_users_user_name ON scim_users (lower(user_name));
CREATE INDEX scim_users_external_id ON scim_users (external_id);

CREATE TABLE scim_groups (
    id           text PRIMARY KEY,
    display_name text NOT NULL,
    external_id  text NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL,
    updated_at   timestamptz NOT NULL
);
CREATE UNIQUE INDEX scim_groups_display_name ON scim_groups (lower(display_name));
CREATE INDEX scim_groups_external_id ON scim_groups (external_id);

CREATE TABLE scim_group_members (
    group_id text NOT NULL REFERENCES scim_groups (id) ON DELETE CASCADE,
    user_id  text NOT NULL REFERENCES scim_users (id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, user_id)
);
CREATE INDEX scim_group_members_user_id ON scim_group_members (user_id);

-- Lock-out (deactivation) revokes tokens and deletes sessions by e-mail,
-- case-insensitively.
CREATE INDEX tokens_human_lower ON tokens (lower(human));
CREATE INDEX sessions_email_lower ON sessions (lower(email));
