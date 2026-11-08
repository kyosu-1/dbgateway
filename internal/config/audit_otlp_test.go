package config

import (
	"maps"
	"strings"
	"testing"
)

func parseAudit(t *testing.T, audit string) (*Config, error) {
	t.Helper()
	return Parse([]byte("auth: { dev_login: true }\naudit: " + audit + "\n"))
}

func TestAuditOTLPConfig(t *testing.T) {
	c, err := parseAudit(t, `{ otlp: { endpoint: "otel-collector.internal:4317" } }`)
	if err != nil {
		t.Fatal(err)
	}
	if o := c.Audit.OTLP; o == nil || o.Endpoint != "otel-collector.internal:4317" || o.Insecure {
		t.Fatalf("otlp = %+v", c.Audit.OTLP)
	}

	c, err = parseAudit(t, `{ otlp: { endpoint: "collector.example.com:4317", insecure: true } }`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(c.Warnings, "\n"), "without TLS") {
		t.Errorf("warnings = %q", c.Warnings)
	}
	c, err = parseAudit(t, `{ otlp: { endpoint: "127.0.0.1:4317", insecure: true } }`)
	if err != nil || len(c.Warnings) != 0 {
		t.Errorf("loopback insecure: %v %q", err, c.Warnings)
	}

	for _, bad := range []string{`""`, `"https://collector:4317"`, `"collector"`, `":4317"`} {
		if _, err := parseAudit(t, `{ otlp: { endpoint: `+bad+` } }`); err == nil || !strings.Contains(err.Error(), "audit.otlp.endpoint") {
			t.Errorf("endpoint %s: err = %v", bad, err)
		}
	}
	if _, err := parseAudit(t, `{ otlp: { endpoint: "c:4317", unknown: 1 } }`); err == nil {
		t.Error("unknown field accepted")
	}
}

func TestAuditOTLPHeaders(t *testing.T) {
	o := &AuditOTLP{Endpoint: "c:4317", HeadersEnv: "DBGW_TEST_OTLP_HEADERS"}
	if _, err := o.Headers(); err == nil {
		t.Error("expected error for an unset variable")
	}
	c, err := parseAudit(t, `{ otlp: { endpoint: "c:4317", headers_env: DBGW_TEST_OTLP_HEADERS } }`)
	if err != nil || !strings.Contains(strings.Join(c.Warnings, "\n"), "is not set") {
		t.Errorf("unset headers env: %v %q", err, c.Warnings)
	}

	t.Setenv("DBGW_TEST_OTLP_HEADERS", "Authorization=Bearer%20abc, x-tenant=team-a,")
	h, err := o.Headers()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"authorization": "Bearer abc", "x-tenant": "team-a"}
	if !maps.Equal(h, want) {
		t.Errorf("headers = %v", h)
	}

	t.Setenv("DBGW_TEST_OTLP_HEADERS", "secretvalue")
	_, err = o.Headers()
	if err == nil || strings.Contains(err.Error(), "secretvalue") {
		t.Errorf("malformed: err = %v (must not echo the value)", err)
	}
	if _, err := parseAudit(t, `{ otlp: { endpoint: "c:4317", headers_env: DBGW_TEST_OTLP_HEADERS } }`); err == nil {
		t.Error("malformed headers accepted")
	}
	if h, err := (&AuditOTLP{}).Headers(); h != nil || err != nil {
		t.Errorf("no headers_env: %v %v", h, err)
	}
}
