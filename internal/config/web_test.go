package config

import (
	"strings"
	"testing"
)

func TestAuditorsConfig(t *testing.T) {
	const base = "auth: { dev_login: true }\ngroups: [{ name: security, members: [ken@example.com] }]\n"
	c, err := Parse([]byte(base + "auditors: [{ group: security }, { user: hanako@example.com }]\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		email  string
		groups []string
		want   bool
	}{
		{"ken@example.com", []string{"security"}, true},
		{"HANAKO@example.com", nil, true},
		{"taro@example.com", []string{"dev"}, false},
		{"", []string{"security"}, false},
	} {
		if got := c.IsAuditor(tt.email, tt.groups); got != tt.want {
			t.Errorf("IsAuditor(%q, %v) = %v", tt.email, tt.groups, got)
		}
	}
	for yaml, want := range map[string]string{
		"auditors: [{ group: nope }]\n":                          "unknown group",
		"auditors: [{ user: a@example.com, group: security }]\n": "exactly one",
		"auditors: [{}]\n":                                       "exactly one",
		"auditors: [{ user: not-an-email }]\n":                   "not an e-mail",
	} {
		if _, err := Parse([]byte(base + yaml)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v, want %q", yaml, err, want)
		}
	}
}

func TestPasskeysConfig(t *testing.T) {
	// Passkeys alone are a login method.
	if _, err := Parse([]byte("server: { public_url: https://dbgw.example.com }\nauth: { passkeys: true }\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse([]byte("server: { public_url: https://dbgw.example.com }\nauth: {}\n")); err == nil {
		t.Fatal("no login method accepted")
	}
	// WebAuthn relying party IDs cannot be IP addresses.
	if _, err := Parse([]byte("auth: { passkeys: true }\n")); err == nil || !strings.Contains(err.Error(), "auth.passkeys") {
		t.Fatalf("IP public_url: err = %v", err)
	}
}
