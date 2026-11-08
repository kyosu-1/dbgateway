package config

import (
	"strings"
	"testing"
)

func TestSCIMConfig(t *testing.T) {
	const base = "auth: { dev_login: true }\n"
	if _, err := Parse([]byte(base + "scim: { enabled: true }\n")); err == nil || !strings.Contains(err.Error(), "scim.token_env") {
		t.Fatalf("missing token_env: err = %v", err)
	}
	const enabled = base + "scim: { enabled: true, token_env: DBGW_TEST_SCIM_CFG }\n"
	for _, tt := range []struct {
		token, warning string
	}{
		{"", "is not set"},
		{"short", "shorter than"},
		{strings.Repeat("x", 40), ""},
	} {
		t.Setenv("DBGW_TEST_SCIM_CFG", tt.token)
		c, err := Parse([]byte(enabled))
		if err != nil {
			t.Fatal(err)
		}
		if !c.SCIM.Enabled {
			t.Fatal("not enabled")
		}
		got := ""
		for _, w := range c.Warnings {
			if strings.HasPrefix(w, "scim.") {
				got = w
			}
		}
		if (tt.warning == "") != (got == "") || !strings.Contains(got, tt.warning) {
			t.Errorf("token %q: warning = %q, want %q", tt.token, got, tt.warning)
		}
	}
	if _, err := Parse([]byte(base + "scim: { enabled: false }\n")); err != nil {
		t.Fatal(err)
	}
}
