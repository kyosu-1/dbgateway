package postgres

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/jackc/pgx/v5/pgproto3"
	"golang.org/x/oauth2"

	"github.com/kyosu-1/dbgateway/internal/config"
)

// fakeTokens replaces the cloud credential lookup for the test and returns
// the number of tokens issued.
func fakeTokens(t *testing.T, lifetime time.Duration) *atomic.Int64 {
	t.Helper()
	var n atomic.Int64
	orig := tokenFetcherFactory
	tokenFetcherFactory = func(_ context.Context, ep config.Endpoint, user string) (tokenFetcher, error) {
		return func(context.Context) (string, time.Time, error) {
			i := n.Add(1)
			return ep.Auth + ":" + user + ":" + strconv.FormatInt(i, 10), time.Now().Add(lifetime), nil
		}, nil
	}
	t.Cleanup(func() { tokenFetcherFactory = orig })
	return &n
}

func iamEndpoint(auth, sslmode string) config.Endpoint {
	return config.Endpoint{Host: "db.example.internal", Port: 5432, DBName: "app", Auth: auth, SSLMode: sslmode}
}

func TestConfigureAuthPassword(t *testing.T) {
	t.Setenv("DBGW_TEST_PW", "s3cret")
	pool, err := newPool(context.Background(), config.Endpoint{Host: "127.0.0.1", Port: 1, DBName: "app", Auth: "password", SSLMode: "disable"}, "reader", "DBGW_TEST_PW", true)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	cc := pool.Config().ConnConfig
	if cc.User != "reader" || cc.Password != "s3cret" {
		t.Errorf("user/password = %q/%q", cc.User, cc.Password)
	}
	if pool.Config().BeforeConnect != nil {
		t.Error("password auth must not install BeforeConnect")
	}

	_, err = newPool(context.Background(), config.Endpoint{Host: "127.0.0.1", Port: 1, Auth: "password", SSLMode: "disable"}, "reader", "DBGW_TEST_UNSET_PW", true)
	if err == nil || !strings.Contains(err.Error(), "DBGW_TEST_UNSET_PW") {
		t.Errorf("unset env: err = %v", err)
	}
}

func TestConfigureAuthIAMRequiresTLS(t *testing.T) {
	fakeTokens(t, 15*time.Minute)
	for _, auth := range []string{"aws_iam", "gcp_iam"} {
		for _, mode := range []string{"disable", "allow", "prefer"} {
			_, err := newPool(context.Background(), iamEndpoint(auth, mode), "dbgw_iam", "", true)
			if err == nil || !strings.Contains(err.Error(), "requires TLS") {
				t.Errorf("%s sslmode=%s: err = %v", auth, mode, err)
			}
		}
		for _, mode := range []string{"require", "verify-ca", "verify-full"} {
			p, err := newPool(context.Background(), iamEndpoint(auth, mode), "dbgw_iam", "", true)
			if err != nil {
				t.Errorf("%s sslmode=%s: %v", auth, mode, err)
				continue
			}
			p.Close()
		}
	}
}

func TestConfigureAuthIAMRejectsPassword(t *testing.T) {
	fakeTokens(t, 15*time.Minute)
	t.Setenv("DBGW_TEST_PW", "x")
	if _, err := newPool(context.Background(), iamEndpoint("aws_iam", "require"), "u", "DBGW_TEST_PW", true); err == nil {
		t.Fatal("expected an error for password_env with aws_iam")
	}
}

func TestConfigureAuthIAMBeforeConnect(t *testing.T) {
	n := fakeTokens(t, 15*time.Minute)
	t.Setenv("PGPASSWORD", "must-not-be-used")
	pool, err := newPool(context.Background(), iamEndpoint("aws_iam", "verify-full"), "dbgw_iam", "", true)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	pc := pool.Config()
	if pc.ConnConfig.Password != "" {
		t.Errorf("static password = %q, want empty", pc.ConnConfig.Password)
	}
	if pc.BeforeConnect == nil {
		t.Fatal("BeforeConnect not set")
	}
	for range 3 {
		cc := pc.ConnConfig.Copy()
		if err := pc.BeforeConnect(context.Background(), cc); err != nil {
			t.Fatal(err)
		}
		if cc.Password != "aws_iam:dbgw_iam:1" {
			t.Errorf("password = %q", cc.Password)
		}
	}
	if n.Load() != 1 {
		t.Errorf("tokens issued = %d, want 1 (cached)", n.Load())
	}
}

func TestTokenCache(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var calls int
	c := &tokenCache{
		margin: 5 * time.Minute,
		now:    func() time.Time { return now },
		fetch: func(context.Context) (string, time.Time, error) {
			calls++
			return "tok" + strconv.Itoa(calls), now.Add(15 * time.Minute), nil
		},
	}
	get := func() string {
		t.Helper()
		tok, err := c.token(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	if get() != "tok1" {
		t.Fatal("first token")
	}
	now = now.Add(9 * time.Minute)
	if got := get(); got != "tok1" {
		t.Errorf("after 9m: %s, want cached tok1", got)
	}
	now = now.Add(2 * time.Minute) // 11m: less than 5m left
	if got := get(); got != "tok2" {
		t.Errorf("after 11m: %s, want refreshed tok2", got)
	}

	// Errors and expired tokens are not cached and fail the login.
	c.fetch = func(context.Context) (string, time.Time, error) { return "", time.Time{}, errors.New("no credentials") }
	now = now.Add(time.Hour)
	if _, err := c.token(context.Background()); err == nil {
		t.Error("expected fetch error")
	}
	c.fetch = func(context.Context) (string, time.Time, error) { return "old", now.Add(-time.Second), nil }
	if _, err := c.token(context.Background()); err == nil {
		t.Error("expected error for an expired token")
	}
}

func TestAWSTokenFetcher(t *testing.T) {
	creds := credentials.NewStaticCredentialsProvider("AKIDEXAMPLE", "secret", "")
	fetch := awsTokenFetcher(config.Endpoint{Host: "db.abc.ap-northeast-1.rds.amazonaws.com", Port: 5432}, "dbgw_iam", "ap-northeast-1", creds)
	tok, exp, err := fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if time.Until(exp) > awsTokenLifetime || time.Until(exp) < awsTokenLifetime-time.Minute {
		t.Errorf("expiry %v", exp)
	}
	if !strings.HasPrefix(tok, "db.abc.ap-northeast-1.rds.amazonaws.com:5432?") {
		t.Fatalf("token = %s", tok)
	}
	q, err := url.ParseQuery(tok[strings.Index(tok, "?")+1:])
	if err != nil {
		t.Fatal(err)
	}
	if q.Get("Action") != "connect" || q.Get("DBUser") != "dbgw_iam" || q.Get("X-Amz-Expires") != "900" {
		t.Errorf("query = %v", q)
	}
	if !strings.Contains(q.Get("X-Amz-Credential"), "/ap-northeast-1/rds-db/aws4_request") {
		t.Errorf("credential scope = %s", q.Get("X-Amz-Credential"))
	}
}

func TestGCPTokenFetcher(t *testing.T) {
	exp := time.Now().Add(time.Hour).Truncate(time.Second)
	fetch := gcpTokenFetcher(oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "ya29.x", Expiry: exp}))
	tok, got, err := fetch(context.Background())
	if err != nil || tok != "ya29.x" || !got.Equal(exp) {
		t.Errorf("token = %q %v %v", tok, got, err)
	}
	fetch = gcpTokenFetcher(oauth2.StaticTokenSource(&oauth2.Token{}))
	if _, _, err := fetch(context.Background()); err == nil {
		t.Error("expected an error for an empty token")
	}
}

// TestIAMTokenOnTheWire runs a minimal PostgreSQL server that requires TLS
// and a cleartext password, and checks that each new connection logs in
// with the token from BeforeConnect.
func TestIAMTokenOnTheWire(t *testing.T) {
	fakeTokens(t, 15*time.Minute)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	passwords := make(chan string, 4)
	go serveFakePostgres(t, ln, selfSignedTLS(t), passwords)

	port := ln.Addr().(*net.TCPAddr).Port
	ep := config.Endpoint{Host: "127.0.0.1", Port: port, DBName: "app", Auth: "gcp_iam", SSLMode: "require"}
	pool, err := newPool(context.Background(), ep, "dbgw-sa@proj.iam", "", true)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c1, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := pool.Acquire(ctx) // a second physical connection
	if err != nil {
		t.Fatal(err)
	}
	c1.Release()
	c2.Release()
	for range 2 {
		select {
		case pw := <-passwords:
			if pw != "gcp_iam:dbgw-sa@proj.iam:1" {
				t.Errorf("password on the wire = %q", pw)
			}
		case <-ctx.Done():
			t.Fatal("no login")
		}
	}
}

func serveFakePostgres(t *testing.T, ln net.Listener, tc *tls.Config, passwords chan<- string) {
	for {
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		go func(raw net.Conn) {
			defer raw.Close()
			be := pgproto3.NewBackend(raw, raw)
			msg, err := be.ReceiveStartupMessage()
			if err != nil {
				return
			}
			if _, ok := msg.(*pgproto3.SSLRequest); !ok {
				t.Errorf("first message %T, want SSLRequest (TLS is required)", msg)
				return
			}
			if _, err := raw.Write([]byte{'S'}); err != nil {
				return
			}
			conn := tls.Server(raw, tc)
			be = pgproto3.NewBackend(conn, conn)
			if _, err := be.ReceiveStartupMessage(); err != nil {
				return
			}
			be.Send(&pgproto3.AuthenticationCleartextPassword{})
			if err := be.Flush(); err != nil {
				return
			}
			if err := be.SetAuthType(pgproto3.AuthTypeCleartextPassword); err != nil {
				return
			}
			msg, err = be.Receive()
			if err != nil {
				return
			}
			pm, ok := msg.(*pgproto3.PasswordMessage)
			if !ok {
				return
			}
			passwords <- pm.Password
			be.Send(&pgproto3.AuthenticationOk{})
			be.Send(&pgproto3.BackendKeyData{ProcessID: 1, SecretKey: []byte{0, 0, 0, 1}})
			be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
			if err := be.Flush(); err != nil {
				return
			}
			for {
				if _, err := be.Receive(); err != nil {
					return
				}
			}
		}(raw)
	}
}

func selfSignedTLS(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "fake-postgres"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
}
