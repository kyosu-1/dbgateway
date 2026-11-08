package config

import (
	"net"
	"time"
)

// PGProxy configures the PostgreSQL wire-protocol proxy (`pgproxy:`). The
// proxy is disabled when Listen is empty.
type PGProxy struct {
	// Listen is the TCP address to accept PostgreSQL clients on, for
	// example 127.0.0.1:5433.
	Listen string `yaml:"listen"`
	// TLSCert and TLSKey are PEM files. They are required unless Listen is
	// a loopback address, because clients send their token as a cleartext
	// password.
	TLSCert string `yaml:"tls_cert"`
	TLSKey  string `yaml:"tls_key"`
	// MaxConnections bounds concurrent client connections (default 100).
	MaxConnections int `yaml:"max_connections"`
	// IdleTimeout closes connections that send nothing for this long
	// (default 30m).
	IdleTimeout Duration `yaml:"idle_timeout"`
}

// Default values of the pgproxy section.
const (
	DefaultPGProxyMaxConnections = 100
	DefaultPGProxyIdleTimeout    = 30 * time.Minute
)

// Enabled reports whether the proxy should be started.
func (p *PGProxy) Enabled() bool { return p.Listen != "" }

// TLSEnabled reports whether a certificate is configured.
func (p *PGProxy) TLSEnabled() bool { return p.TLSCert != "" && p.TLSKey != "" }

// validatePGProxy applies the section's defaults and validates it.
func (c *Config) validatePGProxy(add func(string, ...any)) {
	p := &c.PGProxy
	if p.MaxConnections == 0 {
		p.MaxConnections = DefaultPGProxyMaxConnections
	}
	if p.IdleTimeout == 0 {
		p.IdleTimeout = Duration(DefaultPGProxyIdleTimeout)
	}
	if p.MaxConnections < 0 {
		add("pgproxy.max_connections: must be positive")
	}
	if p.IdleTimeout < 0 {
		add("pgproxy.idle_timeout: must be positive")
	}
	if (p.TLSCert == "") != (p.TLSKey == "") {
		add("pgproxy: tls_cert and tls_key must be set together")
	}
	if !p.Enabled() {
		return
	}
	if _, _, err := net.SplitHostPort(p.Listen); err != nil {
		add("pgproxy.listen: must be host:port (%v)", err)
		return
	}
	if !p.TLSEnabled() && !isLoopbackListen(p.Listen) {
		add("pgproxy: tls_cert and tls_key are required unless pgproxy.listen is a loopback address (tokens are sent as passwords)")
	}
}
