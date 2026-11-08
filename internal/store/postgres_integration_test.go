//go:build integration

// Integration tests of the PostgreSQL backend against the development
// PostgreSQL:
//
//	docker compose -f examples/dev/compose.yaml up -d --wait
//	go test -tags integration ./internal/store/
//
// Each run creates a database with a random name as the superuser and
// drops it afterwards. The connection is configured with the same
// DBGW_TEST_PG_* variables as the other integration tests.
package store_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kyosu-1/dbgateway/internal/store"
	"github.com/kyosu-1/dbgateway/internal/store/storetest"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// pgDSN returns the DSN of database db on the test server.
func pgDSN(db string) string {
	u := url.URL{Scheme: "postgres", Host: env("DBGW_TEST_PG_HOST", "127.0.0.1") + ":" + env("DBGW_TEST_PG_PORT", "55432"), Path: "/" + db,
		User: url.UserPassword(env("DBGW_TEST_PG_SUPERUSER", "postgres"), env("DBGW_TEST_PG_SUPERPASSWORD", "postgres"))}
	q := url.Values{"sslmode": {env("DBGW_TEST_PG_SSLMODE", "disable")}}
	if rc := env("DBGW_TEST_PG_SSLROOTCERT", ""); rc != "" {
		q.Set("sslrootcert", rc)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// tempDatabase creates an empty database and drops it when the test ends.
func tempDatabase(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, pgDSN(env("DBGW_TEST_PG_DB", "app")))
	if err != nil {
		t.Fatalf("connect as superuser: %v", err)
	}
	b := make([]byte, 6)
	rand.Read(b)
	name := "dbgw_store_test_" + hex.EncodeToString(b)
	if _, err := admin.Exec(ctx, `CREATE DATABASE `+pgx.Identifier{name}.Sanitize()); err != nil {
		admin.Close(ctx)
		t.Fatalf("create database: %v", err)
	}
	t.Cleanup(func() {
		defer admin.Close(ctx)
		if _, err := admin.Exec(ctx, `DROP DATABASE `+pgx.Identifier{name}.Sanitize()+` WITH (FORCE)`); err != nil {
			t.Errorf("drop database %s: %v", name, err)
		}
	})
	return pgDSN(name)
}

func openPG(t *testing.T, dsn string) *store.Postgres {
	t.Helper()
	s, err := store.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// truncateAll empties every table except schema_migrations.
func truncateAll(t *testing.T, dsn string) {
	t.Helper()
	ctx := context.Background()
	c, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(ctx)
	rows, err := c.Query(ctx, `SELECT tablename FROM pg_tables WHERE schemaname = current_schema() AND tablename <> 'schema_migrations'`)
	if err != nil {
		t.Fatal(err)
	}
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	if len(names) == 0 {
		return
	}
	q := "TRUNCATE "
	for i, n := range names {
		if i > 0 {
			q += ", "
		}
		q += pgx.Identifier{n}.Sanitize()
	}
	if _, err := c.Exec(ctx, q+" CASCADE"); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresConformance(t *testing.T) {
	dsn := tempDatabase(t)
	openPG(t, dsn) // migrate once
	storetest.Run(t, storetest.Harness{
		Open: func(t *testing.T) storetest.Backend {
			truncateAll(t, dsn)
			return openPG(t, dsn)
		},
		OpenInstances: func(t *testing.T, n int) []storetest.Backend {
			truncateAll(t, dsn)
			out := make([]storetest.Backend, n)
			for i := range out {
				out[i] = openPG(t, dsn)
			}
			return out
		},
	})
}

// Instances starting together on an empty database apply every migration
// exactly once.
func TestPostgresConcurrentMigrations(t *testing.T) {
	dsn := tempDatabase(t)
	const n = 6
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := range n {
		wg.Go(func() {
			s, err := store.OpenPostgres(context.Background(), dsn)
			if err == nil {
				s.Close()
			}
			errs[i] = err
		})
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	c, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(ctx)
	var count, distinct, max int
	if err := c.QueryRow(ctx, `SELECT COUNT(*), COUNT(DISTINCT version), MAX(version) FROM schema_migrations`).Scan(&count, &distinct, &max); err != nil {
		t.Fatal(err)
	}
	if count != distinct || max < 3 || count != max {
		t.Fatalf("schema_migrations: %d rows, %d distinct, max %d", count, distinct, max)
	}
	// Reopening is a no-op.
	openPG(t, dsn)
}

func TestPostgresTimesAreUTC(t *testing.T) {
	s := openPG(t, tempDatabase(t))
	ctx := context.Background()
	if err := s.UpsertUser(ctx, &store.User{Email: "a@example.com"}); err != nil {
		t.Fatal(err)
	}
	u, err := s.GetUser(ctx, "a@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if u.CreatedAt.Location() != time.UTC || u.LastLoginAt.Location() != time.UTC {
		t.Fatalf("location = %v", u.CreatedAt.Location())
	}
}

func TestOpenPostgresBadDSN(t *testing.T) {
	if _, err := store.OpenPostgres(context.Background(), "postgres://u:secretpw@127.0.0.1:1/x?sslmode=disable&connect_timeout=1"); err == nil {
		t.Fatal("connected to a closed port")
	} else if strings.Contains(err.Error(), "secretpw") {
		t.Fatalf("error leaks the password: %v", err)
	}
}
