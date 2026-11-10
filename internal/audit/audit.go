// Package audit writes the tamper-evident audit log.
//
// Every request is one JSON line. Each line includes the hash of the
// previous line (prev_hash) and its own hash, computed over the line's
// bytes without the trailing hash field, so any edit, deletion or
// reordering breaks the chain. Query result values are never recorded.
package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// GenesisHash is the prev_hash of the very first entry.
var GenesisHash = strings.Repeat("0", 64)

// Entry is one audit record.
type Entry struct {
	TS             string         `json:"ts"`
	RequestID      string         `json:"request_id"`
	TraceID        string         `json:"trace_id,omitempty"`
	Event          string         `json:"event"` // query | search | list
	Principal      PrincipalInfo  `json:"principal"`
	Database       string         `json:"database,omitempty"`
	SQL            string         `json:"sql,omitempty"`
	SQLSHA256      string         `json:"sql_sha256,omitempty"`
	Reason         string         `json:"reason,omitempty"`
	Analysis       *AnalysisInfo  `json:"analysis,omitempty"`
	Estimate       *EstimateInfo  `json:"estimate,omitempty"`
	Decision       string         `json:"decision"` // allow | deny | approve | error
	Stage          string         `json:"stage,omitempty"`
	Rule           string         `json:"rule,omitempty"`
	ShadowDeniedBy string         `json:"shadow_denied_by,omitempty"`
	ConfigVersion  string         `json:"config_version"`
	Result         *ResultInfo    `json:"result,omitempty"`
	Extra          map[string]any `json:"extra,omitempty"`
	PrevHash       string         `json:"prev_hash"`
}

// PrincipalInfo identifies who made the request.
type PrincipalInfo struct {
	Kind       string `json:"kind"`
	Human      string `json:"human"`
	Agent      string `json:"agent,omitempty"`
	ClientID   string `json:"client_id,omitempty"`
	ClientName string `json:"client_name,omitempty"` // self-reported
}

// AnalysisInfo summarizes the analysis result.
type AnalysisInfo struct {
	Kind      string   `json:"kind"`
	IsWrite   bool     `json:"is_write,omitempty"`
	Tables    []string `json:"tables,omitempty"`
	Columns   []string `json:"columns,omitempty"`
	Functions []string `json:"functions,omitempty"`
	Unknown   bool     `json:"unknown,omitempty"`
}

// EstimateInfo is the planner estimate used for the decision.
type EstimateInfo struct {
	Rows float64 `json:"rows"`
	Cost float64 `json:"cost"`
}

// ResultInfo describes the execution outcome without any values.
type ResultInfo struct {
	Rows          int      `json:"rows"`
	Bytes         int64    `json:"bytes"`
	DurationMS    int64    `json:"duration_ms"`
	Truncated     bool     `json:"truncated"`
	MaskedColumns []string `json:"masked_columns,omitempty"`
	Error         *string  `json:"error"`
}

// Sink stores encoded lines.
type Sink interface {
	// LastHash returns the hash of the last stored line (GenesisHash if empty).
	LastHash() (string, error)
	// Append durably stores one line (without the trailing newline).
	Append(line []byte, at time.Time) error
	Close() error
}

// Logger appends entries to a sink, maintaining the hash chain.
type Logger struct {
	mu   sync.Mutex
	sink Sink
	prev string
	now  func() time.Time
	// onError is told about every entry that could not be written.
	onError func(error)
}

// New returns a logger on sink, continuing its existing chain.
func New(sink Sink) (*Logger, error) {
	prev, err := sink.LastHash()
	if err != nil {
		return nil, fmt.Errorf("audit: read last hash: %w", err)
	}
	return &Logger{sink: sink, prev: prev, now: time.Now}, nil
}

// SetErrorObserver sets f to be called, synchronously, for every entry
// that could not be written (used for metrics). f must not block.
func (l *Logger) SetErrorObserver(f func(error)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.onError = f
}

// Write appends e. If it returns an error the caller must not return the
// query result (fail closed).
func (l *Logger) Write(e *Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	err := l.write(e)
	if err != nil && l.onError != nil {
		l.onError(err)
	}
	return err
}

func (l *Logger) write(e *Entry) error {
	now := l.now()
	if e.TS == "" {
		e.TS = now.Format(time.RFC3339Nano)
	}
	e.PrevHash = l.prev
	line, hash, err := Encode(e)
	if err != nil {
		return err
	}
	if err := l.sink.Append(line, now); err != nil {
		return fmt.Errorf("audit: write: %w", err)
	}
	l.prev = hash
	return nil
}

// Close closes the sink.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.sink.Close()
}

// Encode serializes e and appends its hash. It returns the line and hash.
func Encode(e *Entry) ([]byte, string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(e); err != nil {
		return nil, "", err
	}
	body := bytes.TrimRight(buf.Bytes(), "\n")
	sum := sha256.Sum256(body)
	hash := hex.EncodeToString(sum[:])
	line := make([]byte, 0, len(body)+80)
	line = append(line, body[:len(body)-1]...)
	line = append(line, `,"hash":"`...)
	line = append(line, hash...)
	line = append(line, `"}`...)
	return line, hash, nil
}

const hashSuffixLen = len(`,"hash":"`) + 64 + len(`"}`)

// errChain is returned for chain verification failures.
var errChain = errors.New("audit chain broken")

// checkLine verifies one line's own hash and returns (hash, prev_hash).
func checkLine(line []byte) (string, string, error) {
	if len(line) < hashSuffixLen+2 || !bytes.HasPrefix(line[len(line)-hashSuffixLen:], []byte(`,"hash":"`)) {
		return "", "", fmt.Errorf("%w: missing hash field", errChain)
	}
	hash := string(line[len(line)-66 : len(line)-2])
	body := append(append([]byte{}, line[:len(line)-hashSuffixLen]...), '}')
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != hash {
		return "", "", fmt.Errorf("%w: hash mismatch (line was modified)", errChain)
	}
	var meta struct {
		PrevHash string `json:"prev_hash"`
	}
	if err := json.Unmarshal(line, &meta); err != nil {
		return "", "", fmt.Errorf("%w: invalid JSON", errChain)
	}
	return hash, meta.PrevHash, nil
}
