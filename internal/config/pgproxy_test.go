package config

import (
	"strings"
	"testing"
	"time"
)

func TestPGProxyConfig(t *testing.T) {
	const base = "auth: { dev_login: true }\n"
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{name: "disabled", yaml: ""},
		{name: "loopback without TLS", yaml: "pgproxy: { listen: 127.0.0.1:5433 }"},
		{name: "localhost without TLS", yaml: "pgproxy: { listen: localhost:5433 }"},
		{name: "public without TLS", yaml: "pgproxy: { listen: 0.0.0.0:5433 }", wantErr: "tls_cert and tls_key are required"},
		{name: "empty host without TLS", yaml: "pgproxy: { listen: ':5433' }", wantErr: "tls_cert and tls_key are required"},
		{name: "public with TLS", yaml: "pgproxy: { listen: 0.0.0.0:5433, tls_cert: c.pem, tls_key: k.pem }"},
		{name: "cert without key", yaml: "pgproxy: { listen: 127.0.0.1:5433, tls_cert: c.pem }", wantErr: "set together"},
		{name: "bad listen", yaml: "pgproxy: { listen: '5433' }", wantErr: "pgproxy.listen"},
		{name: "negative max", yaml: "pgproxy: { listen: 127.0.0.1:5433, max_connections: -1 }", wantErr: "max_connections"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := Parse([]byte(base + tt.yaml))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if c.PGProxy.MaxConnections != DefaultPGProxyMaxConnections || c.PGProxy.IdleTimeout.D() != 30*time.Minute {
				t.Errorf("defaults not applied: %+v", c.PGProxy)
			}
		})
	}
}
