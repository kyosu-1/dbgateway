package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"
)

func testCAPEM(t *testing.T) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

const certYAML = `
auth: { dev_login: true }
store: { driver: postgres, dsn_env: DBGW_T_DSN, sslrootcert_env: DBGW_T_STORE_CA }
databases:
  - name: db
    primary: { host: db.internal, read_user: r, password_env: DBGW_T_PW, sslmode: verify-full, sslrootcert_env: DBGW_T_DB_CA }
`

func TestSSLRootCertFromEnv(t *testing.T) {
	ca := testCAPEM(t)
	t.Setenv("DBGW_T_DB_CA", ca)
	t.Setenv("DBGW_T_STORE_CA", ca)
	t.Setenv("DBGW_T_DSN", "postgres://u:p@store.internal:5432/dbgateway?sslmode=verify-full")
	t.Setenv("DBGW_T_PW", "x")
	cfg, err := Parse([]byte(certYAML))
	if err != nil {
		t.Fatal(err)
	}
	path := cfg.Databases[0].Primary.SSLRootCert
	b, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(b), "BEGIN CERTIFICATE") {
		t.Fatalf("materialized CA %q: %v", path, err)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Errorf("CA file mode = %v", st.Mode().Perm())
	}
	dsn, err := cfg.StoreDSN()
	if err != nil || !strings.Contains(dsn, "sslrootcert=") || !strings.Contains(dsn, "sslmode=verify-full") {
		t.Fatalf("store DSN = %q %v", dsn, err)
	}
	if got := withSSLRootCert("host=a user=b", "/tmp/x.pem"); got != "host=a user=b sslrootcert='/tmp/x.pem'" {
		t.Errorf("keyword DSN = %q", got)
	}

	t.Setenv("DBGW_T_DB_CA", "not a certificate")
	if _, err := Parse([]byte(certYAML)); err == nil || !strings.Contains(err.Error(), "PEM") {
		t.Errorf("invalid PEM: %v", err)
	}
	t.Setenv("DBGW_T_DB_CA", "")
	if _, err := Parse([]byte(certYAML)); err == nil || !strings.Contains(err.Error(), "not set") {
		t.Errorf("unset env: %v", err)
	}
}

func TestLoadFromEnv(t *testing.T) {
	t.Setenv("DBGW_T_CONFIG", "auth: { dev_login: true }\n")
	cfg, err := Load(EnvPrefix + "DBGW_T_CONFIG")
	if err != nil || !cfg.Auth.DevLogin {
		t.Fatalf("Load(env:) = %+v %v", cfg, err)
	}
	if _, err := Load(EnvPrefix + "DBGW_T_UNSET_CONFIG"); err == nil {
		t.Error("empty env must fail")
	}
}
