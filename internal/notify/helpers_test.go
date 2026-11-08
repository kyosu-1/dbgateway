package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/store"
)

// slackCall is one Web API call received by the fake Slack.
type slackCall struct {
	Method string
	Form   url.Values
}

// fakeSlack is a minimal Slack Web API.
type fakeSlack struct {
	t     *testing.T
	srv   *httptest.Server
	mu    sync.Mutex
	calls []slackCall
	seq   int
	// block, when set, makes every call wait until it is closed.
	block chan struct{}
	// fail makes chat.postMessage return an error.
	fail bool
}

func newFakeSlack(t *testing.T) *fakeSlack {
	f := &fakeSlack{t: t}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeSlack) serve(w http.ResponseWriter, r *http.Request) {
	if f.block != nil {
		<-f.block
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	method := strings.TrimPrefix(r.URL.Path, "/")
	f.mu.Lock()
	f.calls = append(f.calls, slackCall{Method: method, Form: r.PostForm})
	f.seq++
	seq := f.seq
	fail := f.fail
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	channelID := func(c string) string {
		if strings.HasPrefix(c, "#") {
			return "C" + strings.ToUpper(strings.NewReplacer("#", "", "-", "").Replace(c))
		}
		return c
	}
	var resp any
	switch method {
	case "chat.postMessage":
		if fail {
			resp = map[string]any{"ok": false, "error": "channel_not_found"}
			break
		}
		resp = map[string]any{"ok": true, "channel": channelID(r.PostForm.Get("channel")), "ts": fmt.Sprintf("1700000000.%06d", seq)}
	case "chat.update":
		resp = map[string]any{"ok": true, "channel": r.PostForm.Get("channel"), "ts": r.PostForm.Get("ts")}
	case "chat.postEphemeral":
		resp = map[string]any{"ok": true, "message_ts": "1700000001.000001"}
	case "conversations.open":
		resp = map[string]any{"ok": true, "channel": map[string]any{"id": "D" + strings.TrimPrefix(r.PostForm.Get("users"), "U")}}
	default:
		resp = map[string]any{"ok": false, "error": "unknown_method"}
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func (f *fakeSlack) snapshot() []slackCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]slackCall(nil), f.calls...)
}

func (f *fakeSlack) byMethod(m string) []slackCall {
	var out []slackCall
	for _, c := range f.snapshot() {
		if c.Method == m {
			out = append(out, c)
		}
	}
	return out
}

// waitFor polls until cond holds.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	end := time.Now().Add(5 * time.Second)
	for time.Now().Before(end) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func openStore(t *testing.T) *store.SQLite {
	t.Helper()
	st, err := store.OpenSQLite(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func testConfig(routes ...config.NotificationRoute) *config.Config {
	return &config.Config{
		Notifications: routes,
		NotificationSettings: config.NotificationSettings{
			Slack:                 &config.SlackSettings{AppTokenEnv: "TEST_SLACK_APP", BotTokenEnv: "TEST_SLACK_BOT"},
			Anomaly:               config.AnomalySettings{DenialsPer10m: 3, RowsPerHour: 1000},
			NotificationsLanguage: "en",
		},
		Groups: []config.Group{{Name: "dba", OIDCGroup: "idp-dba"}},
	}
}

func testEnv(extra map[string]string) func(string) string {
	env := map[string]string{"TEST_SLACK_APP": "xapp-test", "TEST_SLACK_BOT": "xoxb-test"}
	for k, v := range extra {
		env[k] = v
	}
	return func(k string) string { return env[k] }
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// link links email to slackUser directly in the store.
func link(t *testing.T, st *store.SQLite, email, slackUser string) {
	t.Helper()
	l := NewSlackLinker(st, nil, nil)
	code, _, err := l.IssueCode(email)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Link(context.Background(), code, slackUser); err != nil {
		t.Fatal(err)
	}
}

func blockJSON(t *testing.T, b any) string {
	t.Helper()
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return unescapeJSON(string(raw))
}

// unescapeJSON undoes Go's HTML-safe escaping of <, > and & in JSON so
// that tests can look for the characters Slack would see.
func unescapeJSON(s string) string {
	return strings.NewReplacer(`\u003c`, "<", `\u003e`, ">", `\u0026`, "&").Replace(s)
}
