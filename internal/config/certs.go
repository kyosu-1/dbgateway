package config

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// materializeCerts writes CA certificates given through environment
// variables (sslrootcert_env) to private files and points sslrootcert at
// them, so that every driver can use them as files.
func (c *Config) materializeCerts() error {
	var errs []error
	for i := range c.Databases {
		db := &c.Databases[i]
		for _, ep := range []*Endpoint{&db.Primary, db.Replica} {
			if ep == nil || ep.SSLRootCertEnv == "" {
				continue
			}
			path, err := pemFileFromEnv(ep.SSLRootCertEnv)
			if err != nil {
				errs = append(errs, fmt.Errorf("databases %s: sslrootcert_env: %w", db.Name, err))
				continue
			}
			ep.SSLRootCert = path
		}
	}
	if c.Store.SSLRootCertEnv != "" {
		path, err := pemFileFromEnv(c.Store.SSLRootCertEnv)
		if err != nil {
			errs = append(errs, fmt.Errorf("store.sslrootcert_env: %w", err))
		} else {
			c.Store.SSLRootCert = path
		}
	}
	return errors.Join(errs...)
}

// pemFileFromEnv validates the PEM certificates in the environment variable
// and writes them to a file named after their hash in a private directory.
func pemFileFromEnv(name string) (string, error) {
	data := strings.TrimSpace(os.Getenv(name))
	if data == "" {
		return "", fmt.Errorf("environment variable %s is not set", name)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(data)) {
		return "", fmt.Errorf("environment variable %s does not contain PEM certificates", name)
	}
	if b, _ := pem.Decode([]byte(data)); b == nil {
		return "", fmt.Errorf("environment variable %s does not contain PEM certificates", name)
	}
	dir := filepath.Join(os.TempDir(), "dbgateway-certs")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(data))
	path := filepath.Join(dir, hex.EncodeToString(sum[:8])+".pem")
	if err := os.WriteFile(path, []byte(data+"\n"), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// withSSLRootCert adds sslrootcert to a PostgreSQL DSN (URL or keyword form).
func withSSLRootCert(dsn, path string) string {
	if path == "" {
		return dsn
	}
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err == nil {
			q := u.Query()
			q.Set("sslrootcert", path)
			u.RawQuery = q.Encode()
			return u.String()
		}
	}
	return dsn + " sslrootcert='" + strings.ReplaceAll(path, "'", `\'`) + "'"
}
