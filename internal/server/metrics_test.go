package server_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/server"
)

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func newMetricsServer(t *testing.T, listen, metricsListen string) *server.Server {
	t.Helper()
	dir := t.TempDir()
	yaml := fmt.Sprintf(`
server: { listen: "%s", metrics_listen: "%s" }
auth: { dev_login: true }
store: { path: "%[3]s/db.sqlite" }
audit: { dir: "%[3]s/audit" }
`, listen, metricsListen, dir)
	if metricsListen == "" {
		yaml = strings.Replace(yaml, `, metrics_listen: ""`, "", 1)
	}
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := server.New(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	return srv
}

func get(t *testing.T, h http.Handler, path string) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec.Code, rec.Body.String()
}

func TestMetricsOffByDefault(t *testing.T) {
	srv := newMetricsServer(t, "127.0.0.1:8443", "")
	if srv.MetricsHandler() != nil {
		t.Fatal("metrics handler without server.metrics_listen")
	}
	if code, _ := get(t, srv.Handler(), "/metrics"); code != http.StatusNotFound {
		t.Fatalf("main listener /metrics: %d", code)
	}
}

func TestMetricsOnSeparateHandlerOnly(t *testing.T) {
	srv := newMetricsServer(t, "127.0.0.1:8443", "127.0.0.1:9090")
	code, body := get(t, srv.MetricsHandler(), "/metrics")
	if code != http.StatusOK || !strings.Contains(body, "dbgateway_build_info{") || !strings.Contains(body, "go_goroutines ") {
		t.Fatalf("metrics: %d\n%s", code, body)
	}
	// Never on the main (public) listener.
	if code, _ := get(t, srv.Handler(), "/metrics"); code != http.StatusNotFound {
		t.Fatalf("main listener /metrics: %d", code)
	}
	// The metrics listener serves nothing else.
	for _, p := range []string{"/", "/healthz", "/mcp"} {
		if code, _ := get(t, srv.MetricsHandler(), p); code != http.StatusNotFound {
			t.Errorf("metrics listener %s: %d", p, code)
		}
	}
}

func TestRunServesMetricsListener(t *testing.T) {
	listen, metricsListen := freeAddr(t), freeAddr(t)
	srv := newMetricsServer(t, listen, metricsListen)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()

	var body string
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err := http.Get("http://" + metricsListen + "/metrics")
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				body = string(b)
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("metrics listener not ready: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(body, "dbgateway_build_info{") {
		t.Fatalf("metrics body:\n%s", body)
	}
	resp, err := http.Get("http://" + listen + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("main listener /metrics: %d", resp.StatusCode)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("Run did not return")
	}
}

func TestRunFailsWhenMetricsPortIsTaken(t *testing.T) {
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	srv := newMetricsServer(t, freeAddr(t), taken.Addr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Run(ctx); err == nil || !strings.Contains(err.Error(), "server.metrics_listen") {
		t.Fatalf("Run: %v", err)
	}
}
