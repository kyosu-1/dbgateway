package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
)

// AuditOTLP forwards audit entries as OpenTelemetry log records over
// OTLP/gRPC (audit.otlp). Forwarding is best effort: the primary output
// (file / stdout) decides whether a request succeeds.
type AuditOTLP struct {
	// Endpoint is the collector address as host:port (no scheme).
	Endpoint string `yaml:"endpoint"`
	// Insecure disables TLS (plaintext gRPC). Only for a collector on the
	// same host or a trusted network.
	Insecure bool `yaml:"insecure"`
	// HeadersEnv names an environment variable holding gRPC metadata as
	// comma-separated key=value pairs (values URL-encoded), e.g. an API key
	// for a hosted collector: "authorization=Bearer%20xxx,x-tenant=a".
	HeadersEnv string `yaml:"headers_env"`
}

func (o *AuditOTLP) validate(add, warn func(string, ...any)) {
	host, port, err := net.SplitHostPort(o.Endpoint)
	if o.Endpoint == "" || err != nil || host == "" || port == "" || strings.Contains(o.Endpoint, "://") {
		add("audit.otlp.endpoint: must be host:port (e.g. otel-collector.internal:4317)")
		return
	}
	if o.Insecure && !isLoopbackHost(host) {
		warn("audit.otlp.insecure: audit entries are sent to %s without TLS", o.Endpoint)
	}
	if o.HeadersEnv != "" {
		if _, ok := os.LookupEnv(o.HeadersEnv); !ok {
			warn("audit.otlp.headers_env: %s is not set; dbgateway will refuse to start", o.HeadersEnv)
		} else if _, err := o.Headers(); err != nil {
			add("audit.otlp.headers_env: %v", err)
		}
	}
}

// Headers reads and parses the headers from HeadersEnv. It returns nil when
// HeadersEnv is empty, and an error when the variable is unset or malformed.
// The error never includes header values.
func (o *AuditOTLP) Headers() (map[string]string, error) {
	if o.HeadersEnv == "" {
		return nil, nil
	}
	raw, ok := os.LookupEnv(o.HeadersEnv)
	if !ok {
		return nil, fmt.Errorf("environment variable %s is not set", o.HeadersEnv)
	}
	h := map[string]string{}
	for i, pair := range strings.Split(raw, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		k, v, ok := strings.Cut(pair, "=")
		k = strings.ToLower(strings.TrimSpace(k))
		if !ok || k == "" {
			return nil, fmt.Errorf("%s: entry %d is not key=value", o.HeadersEnv, i+1)
		}
		dv, err := url.PathUnescape(strings.TrimSpace(v))
		if err != nil {
			return nil, fmt.Errorf("%s: entry %d (%s) has an invalid escape", o.HeadersEnv, i+1, k)
		}
		h[k] = dv
	}
	return h, nil
}
