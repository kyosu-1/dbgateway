package postgres

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	rdsauth "github.com/aws/aws-sdk-go-v2/feature/rds/auth"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/kyosu-1/dbgateway/internal/config"
)

// gcpLoginScope is the OAuth 2.0 scope for Cloud SQL IAM database
// authentication (the same scope the Cloud SQL Go connector requests for
// its login tokens).
const gcpLoginScope = "https://www.googleapis.com/auth/sqlservice.login"

const (
	// awsTokenLifetime is how long an RDS authentication token is valid.
	awsTokenLifetime = 15 * time.Minute
	// tokenRefreshMargin is the minimum remaining lifetime of a cached
	// token. AWS tokens are therefore reused for 10 minutes; Google access
	// tokens (1 hour) are refreshed 5 minutes before they expire. A token
	// is only checked when a connection logs in, so an established
	// connection outlives its token.
	tokenRefreshMargin = 5 * time.Minute
)

// tokenFetcher obtains a fresh database password and its expiry.
type tokenFetcher func(ctx context.Context) (token string, expiry time.Time, err error)

// tokenFetcherFactory builds the fetcher for an IAM endpoint. It is a
// variable so tests can replace the cloud credential lookup with a fake.
var tokenFetcherFactory = newTokenFetcher

// configureAuth sets the login credentials for the pool's connections:
//
//   - password: the user, and the password from passwordEnv (if set)
//   - aws_iam: an RDS IAM authentication token per new connection
//   - gcp_iam: a Google OAuth 2.0 access token per new connection
//
// IAM tokens are obtained in BeforeConnect, so every new physical connection
// uses a valid token, and are cached to avoid requesting one per connection.
func configureAuth(ctx context.Context, pc *pgxpool.Config, ep config.Endpoint, user, passwordEnv string) error {
	pc.ConnConfig.User = user
	switch ep.Auth {
	case config.AuthPassword, "":
		if passwordEnv != "" {
			pw, ok := os.LookupEnv(passwordEnv)
			if !ok {
				return fmt.Errorf("environment variable %s is not set", passwordEnv)
			}
			pc.ConnConfig.Password = pw
		}
		return nil
	case config.AuthAWSIAM, config.AuthGCPIAM:
	default:
		return fmt.Errorf("unsupported auth method %q", ep.Auth)
	}

	if passwordEnv != "" {
		return fmt.Errorf("auth %s does not use a password; remove the password env setting", ep.Auth)
	}
	// Never send a token over an unencrypted connection: TLS must be
	// mandatory, with no plaintext fallback.
	if pc.ConnConfig.TLSConfig == nil {
		return fmt.Errorf("auth %s requires TLS (sslmode require, verify-ca or verify-full)", ep.Auth)
	}
	for _, fb := range pc.ConnConfig.Fallbacks {
		if fb.TLSConfig == nil {
			return fmt.Errorf("auth %s requires TLS without plaintext fallback (sslmode require, verify-ca or verify-full)", ep.Auth)
		}
	}

	fetch, err := tokenFetcherFactory(ctx, ep, user)
	if err != nil {
		return fmt.Errorf("auth %s: %w", ep.Auth, err)
	}
	cache := &tokenCache{fetch: fetch, margin: tokenRefreshMargin, now: time.Now}
	pc.ConnConfig.Password = "" // ignore PGPASSWORD / .pgpass
	pc.BeforeConnect = func(ctx context.Context, cc *pgx.ConnConfig) error {
		tok, err := cache.token(ctx)
		if err != nil {
			return fmt.Errorf("auth %s: obtain token: %w", ep.Auth, err)
		}
		cc.Password = tok
		return nil
	}
	return nil
}

func newTokenFetcher(ctx context.Context, ep config.Endpoint, user string) (tokenFetcher, error) {
	// The credential providers outlive the Connect call.
	ctx = context.WithoutCancel(ctx)
	switch ep.Auth {
	case config.AuthAWSIAM:
		var opts []func(*awsconfig.LoadOptions) error
		if ep.Region != "" {
			opts = append(opts, awsconfig.WithRegion(ep.Region))
		}
		cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
		if err != nil {
			return nil, fmt.Errorf("load AWS configuration: %w", err)
		}
		if cfg.Region == "" {
			return nil, errors.New("no AWS region: set region on the endpoint or AWS_REGION")
		}
		return awsTokenFetcher(ep, user, cfg.Region, cfg.Credentials), nil
	case config.AuthGCPIAM:
		ts, err := google.DefaultTokenSource(ctx, gcpLoginScope)
		if err != nil {
			return nil, fmt.Errorf("find Google application default credentials: %w", err)
		}
		return gcpTokenFetcher(ts), nil
	}
	return nil, fmt.Errorf("unsupported auth method %q", ep.Auth)
}

// awsTokenFetcher signs RDS IAM authentication tokens. Signing is local
// (SigV4 presigning); only credential retrieval may call AWS.
func awsTokenFetcher(ep config.Endpoint, user, region string, creds aws.CredentialsProvider) tokenFetcher {
	endpoint := net.JoinHostPort(ep.Host, strconv.Itoa(ep.Port))
	return func(ctx context.Context) (string, time.Time, error) {
		issued := time.Now()
		tok, err := rdsauth.BuildAuthToken(ctx, endpoint, region, user, creds)
		if err != nil {
			return "", time.Time{}, err
		}
		return tok, issued.Add(awsTokenLifetime), nil
	}
}

func gcpTokenFetcher(ts oauth2.TokenSource) tokenFetcher {
	return func(context.Context) (string, time.Time, error) {
		tok, err := ts.Token()
		if err != nil {
			return "", time.Time{}, err
		}
		if tok.AccessToken == "" {
			return "", time.Time{}, errors.New("empty access token")
		}
		exp := tok.Expiry
		if exp.IsZero() {
			exp = time.Now().Add(time.Hour)
		}
		return tok.AccessToken, exp, nil
	}
}

// tokenCache reuses a token until less than margin of its lifetime is left.
type tokenCache struct {
	fetch  tokenFetcher
	margin time.Duration
	now    func() time.Time

	mu     sync.Mutex
	tok    string
	expiry time.Time
}

func (c *tokenCache) token(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if c.tok != "" && now.Add(c.margin).Before(c.expiry) {
		return c.tok, nil
	}
	tok, exp, err := c.fetch(ctx)
	if err != nil {
		return "", err
	}
	if tok == "" || !now.Before(exp) {
		return "", errors.New("received an expired or empty token")
	}
	// A token with less than margin left (e.g. an upstream cache handing
	// out its current token) is still used for this login, but the next
	// connection asks again.
	c.tok, c.expiry = tok, exp
	return tok, nil
}
