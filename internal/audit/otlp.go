package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	otellog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
)

// OTLP log record conventions.
const (
	// OTLPEventName is the event name of every forwarded record.
	OTLPEventName = "dbgateway.audit"
	// OTLPScope is the instrumentation scope name.
	OTLPScope = "github.com/kyosu-1/dbgateway/internal/audit"
	// OTLPAttrPrefix prefixes the attributes flattened from the entry
	// ("dbgw.principal.human", "dbgw.analysis.tables", ...).
	OTLPAttrPrefix = "dbgw."
)

// OTLPOptions configures NewOTLPForwarder.
type OTLPOptions struct {
	// Endpoint is the collector address (host:port).
	Endpoint string
	// Insecure disables TLS.
	Insecure bool
	// Headers are sent as gRPC metadata with every export.
	Headers map[string]string
	// Timeout bounds each export (default 10s).
	Timeout time.Duration
	// ServiceInstance is reported as service.instance.id (optional).
	ServiceInstance string
}

// OTLPForwarder sends audit lines as OpenTelemetry log records over
// OTLP/gRPC. The body is the JSON line exactly as stored (so it can be
// re-verified), the attributes are the entry's fields flattened under
// "dbgw." (the SQL text stays in the body only), and "dbgw.hash" carries
// the chain hash. Entries never contain result values.
type OTLPForwarder struct {
	exp    sdklog.Exporter
	lp     *sdklog.LoggerProvider
	logger otellog.Logger
	col    *collectProcessor
}

var _ Forwarder = (*OTLPForwarder)(nil)

// NewOTLPForwarder creates the OTLP/gRPC exporter. The connection is
// established lazily, so an unreachable collector does not fail startup.
func NewOTLPForwarder(ctx context.Context, opt OTLPOptions) (*OTLPForwarder, error) {
	if opt.Endpoint == "" {
		return nil, errors.New("audit otlp: endpoint is required")
	}
	if opt.Timeout <= 0 {
		opt.Timeout = 10 * time.Second
	}
	opts := []otlploggrpc.Option{
		otlploggrpc.WithEndpoint(opt.Endpoint),
		otlploggrpc.WithTimeout(opt.Timeout),
	}
	if opt.Insecure {
		opts = append(opts, otlploggrpc.WithInsecure())
	}
	if len(opt.Headers) > 0 {
		opts = append(opts, otlploggrpc.WithHeaders(opt.Headers))
	}
	exp, err := otlploggrpc.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("audit otlp: %w", err)
	}
	return newOTLPForwarder(exp, opt.ServiceInstance), nil
}

func newOTLPForwarder(exp sdklog.Exporter, instance string) *OTLPForwarder {
	attrs := []attribute.KeyValue{attribute.String("service.name", "dbgateway")}
	if instance != "" {
		attrs = append(attrs, attribute.String("service.instance.id", instance))
	}
	col := &collectProcessor{}
	lp := sdklog.NewLoggerProvider(
		sdklog.WithResource(resource.NewSchemaless(attrs...)),
		sdklog.WithProcessor(col),
	)
	return &OTLPForwarder{exp: exp, lp: lp, logger: lp.Logger(OTLPScope), col: col}
}

// Name implements Forwarder.
func (f *OTLPForwarder) Name() string { return "otlp" }

// Forward converts the batch to log records and exports them in one
// request. MultiSink never calls it concurrently.
func (f *OTLPForwarder) Forward(ctx context.Context, batch []Record) error {
	observed := time.Now()
	for _, r := range batch {
		f.logger.Emit(ctx, toLogRecord(r, observed))
	}
	recs := f.col.take()
	if len(recs) == 0 {
		return nil
	}
	return f.exp.Export(ctx, recs)
}

// Shutdown implements Forwarder.
func (f *OTLPForwarder) Shutdown(ctx context.Context) error {
	return errors.Join(f.lp.Shutdown(ctx), f.exp.Shutdown(ctx))
}

func toLogRecord(r Record, observed time.Time) otellog.Record {
	var rec otellog.Record
	rec.SetEventName(OTLPEventName)
	rec.SetObservedTimestamp(observed)
	rec.SetBody(attribute.StringValue(string(r.Line)))

	var fields map[string]any
	dec := json.NewDecoder(bytes.NewReader(r.Line))
	dec.UseNumber()
	if err := dec.Decode(&fields); err != nil {
		// Still forward the line; the collector can parse the body.
		rec.SetTimestamp(r.At)
		rec.SetSeverity(otellog.SeverityWarn)
		rec.SetSeverityText("WARN")
		rec.AddAttributes(attribute.String(OTLPAttrPrefix+"hash", r.Hash), attribute.Bool(OTLPAttrPrefix+"unparsed", true))
		return rec
	}

	ts := r.At
	if s, ok := fields["ts"].(string); ok {
		if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
			ts = t
		}
	}
	rec.SetTimestamp(ts)
	switch fields["decision"] {
	case "deny", "error":
		rec.SetSeverity(otellog.SeverityWarn)
		rec.SetSeverityText("WARN")
	default:
		rec.SetSeverity(otellog.SeverityInfo)
		rec.SetSeverityText("INFO")
	}

	// The SQL text is in the body; ts is the record timestamp.
	delete(fields, "sql")
	delete(fields, "ts")
	var attrs []attribute.KeyValue
	flatten(OTLPAttrPrefix, fields, &attrs)
	if r.Hash != "" && fields["hash"] == nil {
		attrs = append(attrs, attribute.String(OTLPAttrPrefix+"hash", r.Hash))
	}
	rec.AddAttributes(attrs...)
	return rec
}

// flatten converts nested JSON objects to dotted attribute keys, in key
// order. Arrays of strings become string slices; other arrays are kept as
// their JSON text.
func flatten(prefix string, m map[string]any, out *[]attribute.KeyValue) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		key := prefix + k
		switch v := m[k].(type) {
		case nil:
		case string:
			*out = append(*out, attribute.String(key, v))
		case bool:
			*out = append(*out, attribute.Bool(key, v))
		case json.Number:
			if i, err := v.Int64(); err == nil {
				*out = append(*out, attribute.Int64(key, i))
			} else if f, err := v.Float64(); err == nil {
				*out = append(*out, attribute.Float64(key, f))
			} else {
				*out = append(*out, attribute.String(key, v.String()))
			}
		case map[string]any:
			flatten(key+".", v, out)
		case []any:
			if ss, ok := stringSlice(v); ok {
				*out = append(*out, attribute.StringSlice(key, ss))
			} else if b, err := json.Marshal(v); err == nil {
				*out = append(*out, attribute.String(key, string(b)))
			}
		default:
			if b, err := json.Marshal(v); err == nil {
				*out = append(*out, attribute.String(key, string(b)))
			}
		}
	}
}

func stringSlice(v []any) ([]string, bool) {
	out := make([]string, 0, len(v))
	for _, e := range v {
		s, ok := e.(string)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

// collectProcessor gathers emitted records so that Forward can export a
// whole batch synchronously and report the result (the SDK's batch
// processor would drop silently and hide export errors).
type collectProcessor struct {
	mu   sync.Mutex
	recs []sdklog.Record
}

func (p *collectProcessor) Enabled(context.Context, sdklog.EnabledParameters) bool { return true }

func (p *collectProcessor) OnEmit(_ context.Context, r *sdklog.Record) error {
	p.mu.Lock()
	p.recs = append(p.recs, r.Clone())
	p.mu.Unlock()
	return nil
}

func (p *collectProcessor) take() []sdklog.Record {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := p.recs
	p.recs = nil
	return out
}

func (p *collectProcessor) Shutdown(context.Context) error   { return nil }
func (p *collectProcessor) ForceFlush(context.Context) error { return nil }
