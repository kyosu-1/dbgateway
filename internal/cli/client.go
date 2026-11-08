package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/kyosu-1/dbgateway/gen/dbgateway/v1/dbgatewayv1connect"
)

// bearerTransport adds a bearer token to every request.
type bearerTransport struct {
	base  http.RoundTripper
	token func(context.Context) (string, error)
	// onUnauthorized is called when the server answers 401.
	onUnauthorized func()
}

func (t *bearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	tok, err := t.token(req.Context())
	if err != nil {
		if req.Body != nil {
			req.Body.Close()
		}
		return nil, err
	}
	r := req.Clone(req.Context())
	r.Header.Set("Authorization", "Bearer "+tok)
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	resp, err := base.RoundTrip(r)
	if err == nil && resp.StatusCode == http.StatusUnauthorized && t.onUnauthorized != nil {
		t.onUnauthorized()
	}
	return resp, err
}

func staticToken(tok string) func(context.Context) (string, error) {
	return func(context.Context) (string, error) { return tok, nil }
}

// tokenServiceClient returns a TokenService client authenticated with the
// human credentials.
func tokenServiceClient(c *Credentials) dbgatewayv1connect.TokenServiceClient {
	hc := &http.Client{Timeout: 30 * time.Second, Transport: &bearerTransport{token: staticToken(c.AccessToken)}}
	return dbgatewayv1connect.NewTokenServiceClient(hc, c.Server)
}

// asMetadata is the subset of RFC 8414 metadata the CLI needs.
type asMetadata struct {
	Issuer                      string `json:"issuer"`
	TokenEndpoint               string `json:"token_endpoint"`
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
	RevocationEndpoint          string `json:"revocation_endpoint"`
}

// discover fetches the authorization server metadata and checks that every
// endpoint is on the server itself.
func discover(ctx context.Context, server string) (*asMetadata, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server+"/.well-known/oauth-authorization-server", nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("contact %s: %w", server, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s does not look like a dbgateway server (metadata status %d)", server, resp.StatusCode)
	}
	var m asMetadata
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&m); err != nil {
		return nil, fmt.Errorf("parse server metadata: %w", err)
	}
	if m.Issuer != server {
		return nil, fmt.Errorf("server metadata issuer %q does not match %q", m.Issuer, server)
	}
	if m.DeviceAuthorizationEndpoint == "" || m.TokenEndpoint == "" {
		return nil, fmt.Errorf("server does not support the device flow")
	}
	for _, ep := range []string{m.TokenEndpoint, m.DeviceAuthorizationEndpoint, m.RevocationEndpoint} {
		if ep != "" && !sameOrigin(server, ep) {
			return nil, fmt.Errorf("server metadata points to another origin: %s", ep)
		}
	}
	return &m, nil
}

func sameOrigin(a, b string) bool {
	ua, err1 := url.Parse(a)
	ub, err2 := url.Parse(b)
	return err1 == nil && err2 == nil && ua.Scheme == ub.Scheme && ua.Host == ub.Host
}
