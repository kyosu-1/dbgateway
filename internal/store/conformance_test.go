package store_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/kyosu-1/dbgateway/internal/store"
	"github.com/kyosu-1/dbgateway/internal/store/storetest"
)

// TestSQLiteConformance runs the backend conformance suite on SQLite. The
// PostgreSQL run is in postgres_integration_test.go (build tag
// integration).
func TestSQLiteConformance(t *testing.T) {
	storetest.Run(t, storetest.Harness{
		Open: func(t *testing.T) storetest.Backend {
			return openSQLite(t, ":memory:")
		},
		OpenInstances: func(t *testing.T, n int) []storetest.Backend {
			path := filepath.Join(t.TempDir(), "dbgw.db")
			out := make([]storetest.Backend, n)
			for i := range out {
				out[i] = openSQLite(t, path)
			}
			return out
		},
	})
}

func openSQLite(t *testing.T, path string) *store.SQLite {
	t.Helper()
	s, err := store.OpenSQLite(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
