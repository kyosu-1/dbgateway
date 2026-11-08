package audit

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	otellog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func richEntry() *Entry {
	errMsg := "boom"
	return &Entry{
		TS: "2026-11-08T01:02:03.456Z", RequestID: "req-1", TraceID: "4bf92f3577b34da6a3ce929d0e0e4736", Event: "query",
		Principal: PrincipalInfo{Kind: "agent", Human: "taro@example.com", Agent: "claude-code", ClientID: "cid"},
		Database:  "prod-main", SQL: "SELECT email FROM users WHERE id = $1", SQLSHA256: "abc", Reason: "debug",
		Analysis: &AnalysisInfo{Kind: "select", Tables: []string{"public.users"}, Columns: []string{"public.users.email"}},
		Estimate: &EstimateInfo{Rows: 1, Cost: 8.27},
		Decision: "deny", Stage: "policy", Rule: "no-pii", ConfigVersion: "v1",
		Result:   &ResultInfo{Rows: 0, DurationMS: 3, Error: &errMsg},
		Extra:    map[string]any{"approval_id": "ap-1"},
		PrevHash: GenesisHash,
	}
}

type captureExporter struct {
	mu   sync.Mutex
	recs []sdklog.Record
	err  error
}

func (e *captureExporter) Export(_ context.Context, recs []sdklog.Record) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.err != nil {
		return e.err
	}
	for _, r := range recs {
		e.recs = append(e.recs, r.Clone())
	}
	return nil
}
func (e *captureExporter) Shutdown(context.Context) error   { return nil }
func (e *captureExporter) ForceFlush(context.Context) error { return nil }

func attrMap(r *sdklog.Record) map[string]attribute.Value {
	m := map[string]attribute.Value{}
	r.WalkAttributes(func(kv attribute.KeyValue) bool {
		m[string(kv.Key)] = kv.Value
		return true
	})
	return m
}

func TestOTLPForwarderRecord(t *testing.T) {
	exp := &captureExporter{}
	f := newOTLPForwarder(exp, "gw-1")
	line, hash, err := Encode(richEntry())
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 8, 1, 2, 4, 0, time.UTC)
	if err := f.Forward(context.Background(), []Record{{Line: line, Hash: hash, At: at}}); err != nil {
		t.Fatal(err)
	}
	if len(exp.recs) != 1 {
		t.Fatalf("exported %d records", len(exp.recs))
	}
	r := &exp.recs[0]
	if r.Body().AsString() != string(line) {
		t.Errorf("body = %s", r.Body().AsString())
	}
	if want := time.Date(2026, 11, 8, 1, 2, 3, 456e6, time.UTC); !r.Timestamp().Equal(want) {
		t.Errorf("timestamp = %v", r.Timestamp())
	}
	if r.EventName() != OTLPEventName || r.Severity() != otellog.SeverityWarn {
		t.Errorf("event %q severity %v", r.EventName(), r.Severity())
	}
	if r.InstrumentationScope().Name != OTLPScope {
		t.Errorf("scope = %v", r.InstrumentationScope())
	}
	if v, ok := r.Resource().Set().Value("service.name"); !ok || v.AsString() != "dbgateway" {
		t.Errorf("resource = %v", r.Resource())
	}
	a := attrMap(r)
	wantStr := map[string]string{
		"dbgw.hash":              hash,
		"dbgw.prev_hash":         GenesisHash,
		"dbgw.request_id":        "req-1",
		"dbgw.trace_id":          "4bf92f3577b34da6a3ce929d0e0e4736",
		"dbgw.principal.human":   "taro@example.com",
		"dbgw.principal.agent":   "claude-code",
		"dbgw.database":          "prod-main",
		"dbgw.decision":          "deny",
		"dbgw.rule":              "no-pii",
		"dbgw.analysis.kind":     "select",
		"dbgw.result.error":      "boom",
		"dbgw.extra.approval_id": "ap-1",
		"dbgw.sql_sha256":        "abc",
	}
	for k, want := range wantStr {
		if got := a[k].AsString(); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if got := a["dbgw.analysis.tables"].AsStringSlice(); len(got) != 1 || got[0] != "public.users" {
		t.Errorf("tables = %v", got)
	}
	if a["dbgw.result.duration_ms"].AsInt64() != 3 || a["dbgw.estimate.cost"].AsFloat64() != 8.27 {
		t.Errorf("numbers: %v %v", a["dbgw.result.duration_ms"], a["dbgw.estimate.cost"])
	}
	for _, k := range []string{"dbgw.sql", "dbgw.ts"} {
		if _, ok := a[k]; ok {
			t.Errorf("%s must not be an attribute", k)
		}
	}
}

func TestOTLPForwarderExportError(t *testing.T) {
	exp := &captureExporter{err: errors.New("unavailable")}
	f := newOTLPForwarder(exp, "")
	line, hash, _ := Encode(entry("a"))
	if err := f.Forward(context.Background(), []Record{{Line: line, Hash: hash, At: time.Now()}}); err == nil {
		t.Fatal("export error not reported")
	}
	// The failed batch is not resent with the next one.
	exp.err = nil
	if err := f.Forward(context.Background(), []Record{{Line: line, Hash: hash, At: time.Now()}}); err != nil {
		t.Fatal(err)
	}
	if len(exp.recs) != 1 {
		t.Errorf("exported %d records, want 1", len(exp.recs))
	}
}

// testCollector is an in-process OTLP/gRPC logs receiver.
type testCollector struct {
	collogspb.UnimplementedLogsServiceServer
	mu   sync.Mutex
	recs []*logspb.LogRecord
	md   []metadata.MD
	got  chan struct{}
}

func (c *testCollector) Export(ctx context.Context, req *collogspb.ExportLogsServiceRequest) (*collogspb.ExportLogsServiceResponse, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	c.mu.Lock()
	c.md = append(c.md, md)
	for _, rl := range req.GetResourceLogs() {
		for _, sl := range rl.GetScopeLogs() {
			c.recs = append(c.recs, sl.GetLogRecords()...)
		}
	}
	c.mu.Unlock()
	select {
	case c.got <- struct{}{}:
	default:
	}
	return &collogspb.ExportLogsServiceResponse{}, nil
}

func TestOTLPForwarderGRPC(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	col := &testCollector{got: make(chan struct{}, 1)}
	collogspb.RegisterLogsServiceServer(srv, col)
	go func() { _ = srv.Serve(ln) }()
	defer srv.Stop()

	f, err := NewOTLPForwarder(context.Background(), OTLPOptions{
		Endpoint: ln.Addr().String(), Insecure: true, Headers: map[string]string{"x-dbgw-test": "yes"}, Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	fs, err := OpenFileSink(dir, 0, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	l, err := New(NewMultiSink(fs, f))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"a", "b"} {
		if err := l.Write(entry(id)); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil { // drains the queue
		t.Fatal(err)
	}

	col.mu.Lock()
	defer col.mu.Unlock()
	if len(col.recs) != 2 {
		t.Fatalf("collector received %d records", len(col.recs))
	}
	if v := col.md[0].Get("x-dbgw-test"); len(v) != 1 || v[0] != "yes" {
		t.Errorf("metadata = %v", col.md[0])
	}
	body := col.recs[0].GetBody().GetStringValue()
	hash, _, err := checkLine([]byte(body))
	if err != nil {
		t.Fatalf("forwarded body does not verify: %v", err)
	}
	var found bool
	for _, kv := range col.recs[0].GetAttributes() {
		if kv.GetKey() == "dbgw.hash" {
			found = kv.GetValue().GetStringValue() == hash
		}
	}
	if !found || !strings.Contains(body, `"request_id":"a"`) {
		t.Errorf("record = %v", col.recs[0])
	}
	if rep, err := VerifyDir(dir); err != nil || rep.Entries != 2 {
		t.Errorf("primary: %v %+v", err, rep)
	}
}
