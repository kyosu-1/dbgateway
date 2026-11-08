package policytest

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/kyosu-1/dbgateway/internal/config"
)

// TestRepositoryPolicyFiles runs every policy test file in testdata/policy.
func TestRepositoryPolicyFiles(t *testing.T) {
	files, err := filepath.Glob("../../testdata/policy/*.yaml")
	if err != nil || len(files) == 0 {
		t.Fatalf("no policy test files: %v", err)
	}
	for _, path := range files {
		f, err := Load(path)
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := config.Load(f.Config)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		results, err := Run(context.Background(), f, cfg)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range results {
			if !r.Passed {
				t.Errorf("%s: %s: got %s: %v", filepath.Base(path), r.Name, r.Got, r.Failures)
			}
		}
	}
}
