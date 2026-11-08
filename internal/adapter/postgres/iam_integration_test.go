//go:build integration

// IAM database authentication against a real managed database (RDS with
// deploy/aws, Cloud SQL with deploy/gcp). Skipped unless
// DBGW_TEST_IAM_HOST is set; the setup.sh scripts print the variables.
//
//	go test -tags integration -count=1 -run TestIAMIntegration ./internal/adapter/postgres/
package postgres

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/kyosu-1/dbgateway/internal/analysis"
	"github.com/kyosu-1/dbgateway/internal/config"
)

func TestIAMIntegration(t *testing.T) {
	host := os.Getenv("DBGW_TEST_IAM_HOST")
	if host == "" {
		t.Skip("DBGW_TEST_IAM_HOST is not set")
	}
	port, _ := strconv.Atoi(envOr("DBGW_TEST_IAM_PORT", "5432"))
	user := os.Getenv("DBGW_TEST_IAM_USER")
	ep := config.Endpoint{
		Host:        host,
		Port:        port,
		DBName:      envOr("DBGW_TEST_IAM_DBNAME", "app"),
		Auth:        envOr("DBGW_TEST_IAM_AUTH", "aws_iam"),
		Region:      os.Getenv("DBGW_TEST_IAM_REGION"),
		ReadUser:    user,
		SSLMode:     envOr("DBGW_TEST_IAM_SSLMODE", "verify-full"),
		SSLRootCert: os.Getenv("DBGW_TEST_IAM_SSLROOTCERT"),
	}
	db := &config.Database{Name: "iam-it", Type: "postgres", Primary: ep, SearchPath: []string{"public"}}

	ctx := context.Background()
	a := New(nil)
	c, err := a.Connect(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	opt := analysis.ExecOptions{ReadOnly: true, MaxRows: 10, MaxBytes: 1 << 20, StatementTimeout: 5 * time.Second}
	res, err := a.Execute(ctx, c, "SELECT current_user::text, (SELECT count(*) FROM users)", opt)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(res.Rows) != 1 || res.Rows[0][0] != user {
		t.Fatalf("rows = %v, want current_user %q", res.Rows, user)
	}
	t.Logf("logged in as %v via %s; users = %v", res.Rows[0][0], ep.Auth, res.Rows[0][1])

	// Writes are refused by the database too (read-only grants and
	// default_transaction_read_only).
	if _, err := a.Execute(ctx, c, "DELETE FROM users WHERE id = -1", opt); err == nil {
		t.Error("DELETE succeeded through the read pool")
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
