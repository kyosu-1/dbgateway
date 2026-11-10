package lint

import (
	"slices"
	"testing"
)

// ruleCase is a flagged and a clean example for one rule. The test checks
// that bad reports the rule and good does not.
type ruleCase struct {
	rule string
	bad  string
	good string
}

var pgRuleCases = []ruleCase{
	// CREATE INDEX
	{pgCreateIndexConcurrently,
		"CREATE INDEX users_email ON users (email);",
		"CREATE INDEX CONCURRENTLY users_email ON users (email);"},
	{pgCreateIndexConcurrently,
		"CREATE UNIQUE INDEX ON public.users (email);",
		"CREATE TABLE users (id int PRIMARY KEY, email text);\nCREATE INDEX ON users (email);"},
	{pgDropIndexConcurrently,
		"DROP INDEX users_email;",
		"DROP INDEX CONCURRENTLY users_email;"},
	{pgDropIndexConcurrently,
		"DROP INDEX IF EXISTS a, b;",
		"CREATE TABLE t (id int PRIMARY KEY, x int);\nCREATE INDEX t_x ON t (x);\nDROP INDEX t_x;"},
	{pgConcurrentlyInTransaction,
		"BEGIN;\nCREATE INDEX CONCURRENTLY users_email ON users (email);\nCOMMIT;",
		"BEGIN;\nSELECT 1;\nCOMMIT;\nCREATE INDEX CONCURRENTLY users_email ON users (email);"},
	{pgConcurrentlyInTransaction,
		"START TRANSACTION;\nDROP INDEX CONCURRENTLY users_email;",
		"BEGIN;\nROLLBACK;\nDROP INDEX CONCURRENTLY users_email;"},
	{pgConcurrentlyInTransaction,
		"BEGIN;\nREINDEX (CONCURRENTLY) INDEX users_email;\nCOMMIT;",
		"REINDEX (CONCURRENTLY) INDEX users_email;"},
	{pgConcurrentlyInTransaction,
		"BEGIN;\nCOMMIT AND CHAIN;\nALTER TABLE events DETACH PARTITION events_2020 CONCURRENTLY;",
		"BEGIN;\nCOMMIT;\nALTER TABLE events DETACH PARTITION events_2020 CONCURRENTLY;"},

	// ADD COLUMN
	{pgAddColumnNotNull,
		"ALTER TABLE users ADD COLUMN plan text NOT NULL;",
		"ALTER TABLE users ADD COLUMN plan text NOT NULL DEFAULT 'free';"},
	{pgAddColumnNotNull,
		"ALTER TABLE users ADD COLUMN id2 bigint PRIMARY KEY;",
		"CREATE TABLE t (id int PRIMARY KEY);\nALTER TABLE t ADD COLUMN plan text NOT NULL;"},
	{pgAddColumnVolatileDefault,
		"ALTER TABLE users ADD COLUMN token uuid NOT NULL DEFAULT gen_random_uuid();",
		"ALTER TABLE users ADD COLUMN created_at timestamptz NOT NULL DEFAULT now();"},
	{pgAddColumnVolatileDefault,
		"ALTER TABLE users ADD COLUMN seq bigserial;",
		"ALTER TABLE users ADD COLUMN score int DEFAULT 0;"},
	{pgAddColumnVolatileDefault,
		"ALTER TABLE users ADD COLUMN n bigint GENERATED ALWAYS AS IDENTITY;",
		"CREATE TABLE t (id int PRIMARY KEY);\nALTER TABLE t ADD COLUMN n bigint GENERATED ALWAYS AS IDENTITY;"},
	{pgAddColumnVolatileDefault,
		"ALTER TABLE users ADD COLUMN lower_email text GENERATED ALWAYS AS (lower(email)) STORED;",
		"ALTER TABLE users ADD COLUMN lower_email text;"},

	// Other ALTER TABLE commands
	{pgAlterColumnType,
		"ALTER TABLE users ALTER COLUMN id TYPE bigint;",
		"CREATE TABLE t (id int PRIMARY KEY);\nALTER TABLE t ALTER COLUMN id TYPE bigint;"},
	{pgSetNotNull,
		"ALTER TABLE users ALTER COLUMN email SET NOT NULL;",
		"ALTER TABLE users ADD CONSTRAINT email_nn CHECK (email IS NOT NULL) NOT VALID;\n" +
			"ALTER TABLE users VALIDATE CONSTRAINT email_nn;\n" +
			"ALTER TABLE users ALTER COLUMN email SET NOT NULL;"},
	{pgSetNotNull,
		"ALTER TABLE users ADD CONSTRAINT email_nn CHECK (email IS NOT NULL) NOT VALID;\nALTER TABLE users ALTER COLUMN email SET NOT NULL;",
		"ALTER TABLE users ALTER COLUMN email DROP NOT NULL;"},
	{pgAddConstraintNotValid,
		"ALTER TABLE orders ADD CONSTRAINT orders_user_fk FOREIGN KEY (user_id) REFERENCES users (id);",
		"ALTER TABLE orders ADD CONSTRAINT orders_user_fk FOREIGN KEY (user_id) REFERENCES users (id) NOT VALID;\n" +
			"ALTER TABLE orders VALIDATE CONSTRAINT orders_user_fk;"},
	{pgAddConstraintNotValid,
		"ALTER TABLE orders ADD CONSTRAINT positive CHECK (amount > 0);",
		"ALTER TABLE orders ADD CONSTRAINT positive CHECK (amount > 0) NOT VALID;"},
	{pgConstraintUsingIndex,
		"ALTER TABLE users ADD CONSTRAINT users_email_key UNIQUE (email);",
		"CREATE UNIQUE INDEX CONCURRENTLY users_email_key ON users (email);\n" +
			"ALTER TABLE users ADD CONSTRAINT users_email_key UNIQUE USING INDEX users_email_key;"},
	{pgConstraintUsingIndex,
		"ALTER TABLE users ADD PRIMARY KEY (id);",
		"ALTER TABLE users ADD CONSTRAINT users_pkey PRIMARY KEY USING INDEX users_id_idx;"},
	{pgConstraintUsingIndex,
		"ALTER TABLE users ADD COLUMN handle text UNIQUE;",
		"CREATE TABLE t (id int);\nALTER TABLE t ADD PRIMARY KEY (id);"},
	{pgLockTimeout,
		"ALTER TABLE users ADD COLUMN plan text;",
		"SET lock_timeout = '5s';\nALTER TABLE users ADD COLUMN plan text;"},
	{pgLockTimeout,
		"SET lock_timeout = 0;\nCREATE INDEX ON users (email);",
		"BEGIN;\nSET LOCAL lock_timeout = '3s';\nALTER TABLE users ADD COLUMN plan text;\nCOMMIT;"},
	{pgLockTimeout,
		"SET LOCAL lock_timeout = '3s';\nALTER TABLE users DROP COLUMN plan;",
		"CREATE TABLE t (id int PRIMARY KEY);\nALTER TABLE t ADD COLUMN plan text;"},
	{pgLockTimeout,
		"SET lock_timeout = '5s';\nRESET lock_timeout;\nTRUNCATE users;",
		"ALTER TABLE users VALIDATE CONSTRAINT users_fk;"},
	{pgLockTimeout,
		"BEGIN;\nSET LOCAL lock_timeout = '3s';\nCOMMIT;\nDROP TABLE users;",
		"CREATE INDEX CONCURRENTLY ON users (email);"},

	// Destructive and breaking changes
	{pgDropTable,
		"DROP TABLE IF EXISTS legacy_users CASCADE;",
		"CREATE TABLE tmp (id int PRIMARY KEY);\nDROP TABLE tmp;"},
	{pgDropColumn,
		"ALTER TABLE users DROP COLUMN legacy_flag;",
		"ALTER TABLE users DROP CONSTRAINT users_legacy_check;"},
	{pgRenameTable,
		"ALTER TABLE users RENAME TO accounts;",
		"ALTER INDEX users_email RENAME TO users_email_idx;"},
	{pgRenameTable,
		"ALTER VIEW active_users RENAME TO current_users;",
		"CREATE TABLE t (id int PRIMARY KEY);\nALTER TABLE t RENAME TO t2;"},
	{pgRenameColumn,
		"ALTER TABLE users RENAME COLUMN email TO email_address;",
		"ALTER TABLE users RENAME CONSTRAINT a TO b;"},
	{pgTruncate,
		"TRUNCATE users;",
		"DELETE FROM users WHERE id = 1;"},
	{pgDMLWithoutWhere,
		"UPDATE users SET plan = 'free';",
		"UPDATE users SET plan = 'free' WHERE plan IS NULL;"},
	{pgDMLWithoutWhere,
		"DELETE FROM sessions;",
		"CREATE TABLE t (id int PRIMARY KEY, x int);\nINSERT INTO t VALUES (1, 1);\nUPDATE t SET x = 2;"},

	// CREATE TABLE
	{pgRequirePrimaryKey,
		"CREATE TABLE events (id bigint, payload jsonb);",
		"CREATE TABLE events (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, payload jsonb);"},
	{pgRequirePrimaryKey,
		"CREATE TABLE links (a int, b int, UNIQUE (a, b));",
		"CREATE TABLE links (a int, b int, PRIMARY KEY (a, b));"},
	{pgRequirePrimaryKey,
		"CREATE TABLE links (a int, b int);\nALTER TABLE links ADD CONSTRAINT links_uniq UNIQUE (a, b);",
		"CREATE TABLE links (a int, b int);\nALTER TABLE links ADD PRIMARY KEY (a, b);"},
	{pgRequirePrimaryKey,
		"CREATE UNLOGGED TABLE cache (k text, v text);",
		"CREATE TEMP TABLE scratch (x int);\nCREATE TABLE events_2026 PARTITION OF events FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');\nCREATE TABLE copy (LIKE users INCLUDING ALL);"},
	{pgPreferIdentity,
		"CREATE TABLE t (id serial PRIMARY KEY);",
		"CREATE TABLE t (id int GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY);"},
	{pgPreferIdentity,
		"ALTER TABLE users ADD COLUMN n smallserial;",
		"CREATE TABLE t (id bigint PRIMARY KEY DEFAULT nextval('t_seq'));"},
	{pgPreferTimestamptz,
		"CREATE TABLE t (id int PRIMARY KEY, created_at timestamp NOT NULL);",
		"CREATE TABLE t (id int PRIMARY KEY, created_at timestamptz NOT NULL, d date, t time);"},
	{pgPreferTimestamptz,
		"ALTER TABLE users ALTER COLUMN created_at TYPE timestamp(3) without time zone;",
		"ALTER TABLE users ALTER COLUMN created_at TYPE timestamp with time zone;"},
	{pgPreferText,
		"CREATE TABLE t (id int PRIMARY KEY, name varchar(100));",
		"CREATE TABLE t (id int PRIMARY KEY, name text, code varchar);"},
	{pgPreferText,
		"ALTER TABLE users ADD COLUMN country char(2);",
		"ALTER TABLE users ADD COLUMN country text;"},
}

var mysqlRuleCases = []ruleCase{
	{myDropTable,
		"DROP TABLE IF EXISTS legacy_users;",
		"CREATE TABLE tmp (id int PRIMARY KEY);\nDROP TABLE tmp;\nDROP VIEW v;\nDROP TEMPORARY TABLE t;"},
	{myDropColumn,
		"ALTER TABLE users DROP COLUMN legacy_flag, ALGORITHM=INSTANT;",
		"ALTER TABLE users DROP INDEX idx_legacy, ALGORITHM=INPLACE, LOCK=NONE;"},
	{myRenameTable,
		"RENAME TABLE users TO accounts;",
		"CREATE TABLE t (id int PRIMARY KEY);\nRENAME TABLE t TO t2;"},
	{myRenameTable,
		"ALTER TABLE users RENAME TO accounts, ALGORITHM=INSTANT;",
		"ALTER TABLE users RENAME INDEX a TO b, ALGORITHM=INSTANT;"},
	{myRenameColumn,
		"ALTER TABLE users RENAME COLUMN email TO email_address, ALGORITHM=INSTANT;",
		"ALTER TABLE users ADD COLUMN email_address varchar(255), ALGORITHM=INSTANT;"},
	{myRenameColumn,
		"ALTER TABLE users CHANGE email email_address varchar(255), ALGORITHM=INPLACE;",
		"ALTER TABLE users CHANGE email email varchar(320), ALGORITHM=INPLACE;"},
	{myTruncate,
		"TRUNCATE TABLE users;",
		"DELETE FROM users WHERE id = 1;"},
	{myDMLWithoutWhere,
		"UPDATE users SET plan = 'free';",
		"UPDATE users SET plan = 'free' WHERE plan IS NULL;"},
	{myDMLWithoutWhere,
		"DELETE u FROM users u JOIN bans b ON b.user_id = u.id;",
		"CREATE TABLE t (id int PRIMARY KEY, x int);\nUPDATE t SET x = 1;\nDELETE FROM t;"},
	{myRequirePrimaryKey,
		"CREATE TABLE events (id bigint, payload json);",
		"CREATE TABLE events (id bigint AUTO_INCREMENT PRIMARY KEY, payload json);"},
	{myRequirePrimaryKey,
		"CREATE TABLE links (a int, b int, UNIQUE KEY (a, b));",
		"CREATE TABLE links (a int, b int);\nALTER TABLE links ADD PRIMARY KEY (a, b);\nCREATE TEMPORARY TABLE s (x int);\nCREATE TABLE c LIKE users;"},
	{myAlterAlgorithm,
		"ALTER TABLE users ADD COLUMN plan varchar(20);",
		"ALTER TABLE users ADD COLUMN plan varchar(20), ALGORITHM=INSTANT;"},
	{myAlterAlgorithm,
		"ALTER TABLE users MODIFY plan varchar(40), ALGORITHM=COPY;",
		"ALTER TABLE users ADD INDEX idx_plan (plan), ALGORITHM=INPLACE, LOCK=NONE;"},
	{myAlterAlgorithm,
		"ALTER TABLE users ADD INDEX idx_plan (plan), ALGORITHM=INPLACE, LOCK=SHARED;",
		"CREATE TABLE t (id int PRIMARY KEY);\nALTER TABLE t ADD COLUMN x int;"},
}

func TestRules(t *testing.T) {
	for _, tc := range []struct {
		dialect Dialect
		cases   []ruleCase
	}{{Postgres, pgRuleCases}, {MySQL, mysqlRuleCases}} {
		l, err := New(tc.dialect, nil)
		if err != nil {
			t.Fatal(err)
		}
		tested := map[string]bool{}
		for _, c := range tc.cases {
			tested[c.rule] = true
			t.Run(c.rule, func(t *testing.T) {
				bad := l.Lint("bad.sql", []byte(c.bad))
				if !hasRule(bad, c.rule) {
					t.Errorf("not reported for:\n%s\ngot %+v", c.bad, bad)
				}
				good := l.Lint("good.sql", []byte(c.good))
				if hasRule(good, c.rule) || hasRule(good, SyntaxErrorRule) {
					t.Errorf("reported for:\n%s\ngot %+v", c.good, good)
				}
			})
		}
		for _, r := range Rules(tc.dialect) {
			if !tested[r.ID] {
				t.Errorf("rule %s has no test case", r.ID)
			}
		}
	}
}

func hasRule(fs []Finding, rule string) bool {
	return slices.ContainsFunc(fs, func(f Finding) bool { return f.Rule == rule })
}
