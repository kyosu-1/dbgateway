// Package cli implements the dbgw client subcommands: login, logout, token,
// mcp stdio, and the human query commands (query, explain, dbs, search,
// requests, request). cmd/dbgw wires them into the root command.
package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Credentials are the saved results of `dbgw login`.
type Credentials struct {
	Server      string    `json:"server"`
	AccessToken string    `json:"access_token"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// Valid reports whether the credentials can still be used.
func (c *Credentials) Valid() bool {
	return c != nil && c.AccessToken != "" && time.Until(c.ExpiresAt) > 10*time.Second
}

var errNotLoggedIn = errors.New("not logged in (or the login expired); run `dbgw login`")

// credentialsPath returns the credentials file location. It is a variable
// so tests can redirect it.
var credentialsPath = func() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locate config directory: %w", err)
	}
	return filepath.Join(dir, "dbgw", "credentials.json"), nil
}

func loadCredentials() (*Credentials, error) {
	path, err := credentialsPath()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var c Credentials
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &c, nil
}

// saveCredentials writes the file atomically with 0600 permissions.
func saveCredentials(c *Credentials) error {
	path, err := credentialsPath()
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".credentials-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func deleteCredentials() error {
	path, err := credentialsPath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// resolveServer picks the server URL: flag, then DBGW_SERVER, then the
// saved credentials.
func resolveServer(flag string, saved *Credentials) (string, error) {
	s := flag
	if s == "" {
		s = os.Getenv("DBGW_SERVER")
	}
	if s == "" && saved != nil {
		s = saved.Server
	}
	if s == "" {
		return "", errors.New("no server: pass --server or set DBGW_SERVER")
	}
	return normalizeServer(s)
}

// normalizeServer validates a server URL: https, or http on loopback.
func normalizeServer(s string) (string, error) {
	s = strings.TrimRight(strings.TrimSpace(s), "/")
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("invalid server URL %q", s)
	}
	switch u.Scheme {
	case "https":
	case "http":
		h := u.Hostname()
		if ip := net.ParseIP(h); h != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return "", fmt.Errorf("server URL must use https (plain http is only allowed for localhost)")
		}
	default:
		return "", fmt.Errorf("invalid server URL %q", s)
	}
	return s, nil
}

// loggedIn returns valid saved credentials for the given server flag.
func loggedIn(serverFlag string) (*Credentials, error) {
	c, err := loadCredentials()
	if err != nil {
		return nil, err
	}
	if !c.Valid() {
		return nil, errNotLoggedIn
	}
	if serverFlag != "" || os.Getenv("DBGW_SERVER") != "" {
		s, err := resolveServer(serverFlag, nil)
		if err != nil {
			return nil, err
		}
		if s != c.Server {
			return nil, fmt.Errorf("logged in to %s, not %s; run `dbgw login --server %s`", c.Server, s, s)
		}
	}
	return c, nil
}
