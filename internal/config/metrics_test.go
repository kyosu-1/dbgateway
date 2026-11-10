package config

import (
	"strings"
	"testing"
)

func TestMetricsListenConfig(t *testing.T) {
	const base = "auth: { dev_login: true }\n"

	c, err := Parse([]byte(base))
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.MetricsListen != "" {
		t.Fatalf("metrics enabled by default: %q", c.Server.MetricsListen)
	}

	c, err = Parse([]byte(base + "server: { metrics_listen: 127.0.0.1:9090 }\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.MetricsListen != "127.0.0.1:9090" {
		t.Fatalf("metrics_listen = %q", c.Server.MetricsListen)
	}
	if len(c.Warnings) != 0 {
		t.Fatalf("loopback metrics_listen warned: %v", c.Warnings)
	}

	// Any interface is allowed (Prometheus usually scrapes over the
	// network) but warned about: /metrics has no authentication.
	for _, addr := range []string{"0.0.0.0:9090", ":9090", "10.0.0.5:9090"} {
		c, err := Parse([]byte(base + "server: { metrics_listen: \"" + addr + "\" }\n"))
		if err != nil {
			t.Fatalf("%s: %v", addr, err)
		}
		if len(c.Warnings) != 1 || !strings.Contains(c.Warnings[0], "server.metrics_listen") {
			t.Errorf("%s: warnings = %v", addr, c.Warnings)
		}
	}

	for yaml, want := range map[string]string{
		"server: { metrics_listen: localhost }\n":                                    "host:port",
		"server: { metrics_listen: \"127.0.0.1:\" }\n":                               "port must be",
		"server: { metrics_listen: \"127.0.0.1:metrics\" }\n":                        "port must be",
		"server: { metrics_listen: \"127.0.0.1:70000\" }\n":                          "port must be",
		"server: { metrics_listen: \"127.0.0.1:8443\" }\n":                           "must differ from server.listen",
		"server: { listen: \"0.0.0.0:8443\", metrics_listen: \"127.0.0.1:8443\" }\n": "must differ from server.listen",
		"server: { listen: \"127.0.0.1:8443\", metrics_listen: \"0.0.0.0:8443\" }\n": "must differ from server.listen",
		"server: { metrics_listen: 127.0.0.1:9090, metrics_path: /metrics }\n":       "metrics_path",
		"server: { metrics: { listen: 127.0.0.1:9090 } }\n":                          "metrics",
	} {
		if _, err := Parse([]byte(base + yaml)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v, want %q", yaml, err, want)
		}
	}

	// A different port on the same host is fine.
	const public = "auth: { passkeys: true }\n" +
		"server: { public_url: https://dbgw.example.com, listen: \"0.0.0.0:8443\", metrics_listen: \"0.0.0.0:9090\" }\n"
	if _, err := Parse([]byte(public)); err != nil {
		t.Fatal(err)
	}
}
