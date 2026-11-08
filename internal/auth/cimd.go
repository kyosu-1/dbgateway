package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	cimdTimeout     = 5 * time.Second
	cimdMaxBytes    = 64 << 10
	cimdCacheTTL    = 10 * time.Minute
	cimdNegativeTTL = time.Minute
	cimdMaxEntries  = 1024
	cimdMaxRedirect = 20 // redirect URIs per document
)

// cimdFetcher fetches and caches Client ID Metadata Documents, with SSRF
// protection: https only, no redirects, bounded time and size, and no
// connections to private, loopback or link-local addresses (checked on the
// dialed IP, so DNS rebinding does not help).
type cimdFetcher struct {
	allowInsecure bool // allow http:// and loopback for development
	client        *http.Client

	mu    sync.Mutex
	cache map[string]cimdEntry
}

type cimdEntry struct {
	client  *client
	err     error
	expires time.Time
}

func newCIMDFetcher(allowInsecure bool) *cimdFetcher {
	f := &cimdFetcher{allowInsecure: allowInsecure, cache: map[string]cimdEntry{}}
	dialer := &net.Dialer{Timeout: cimdTimeout, Control: f.checkDial}
	f.client = &http.Client{
		Timeout: cimdTimeout,
		Transport: &http.Transport{
			Proxy:                 nil, // a proxy would defeat the IP check
			DialContext:           dialer.DialContext,
			TLSHandshakeTimeout:   cimdTimeout,
			ResponseHeaderTimeout: cimdTimeout,
			MaxIdleConns:          10,
			IdleConnTimeout:       30 * time.Second,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirects are not allowed") },
	}
	return f
}

// checkDial refuses connections to non-public addresses.
func (f *cimdFetcher) checkDial(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("cimd: unexpected address %q", address)
	}
	ip = ip.Unmap()
	if f.allowInsecure && ip.IsLoopback() {
		return nil
	}
	if !publicIP(ip) {
		return fmt.Errorf("cimd: refusing to connect to non-public address %s", ip)
	}
	return nil
}

var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), // CGNAT
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"), // NAT64 can reach IPv4 internals
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("2001:db8::/32"),
}

func publicIP(ip netip.Addr) bool {
	if !ip.IsValid() || ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
		return false
	}
	for _, p := range nonPublicPrefixes {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

// validateClientIDURL checks the shape of a URL client_id.
func (f *cimdFetcher) validateClientIDURL(id string) error {
	u, err := url.Parse(id)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || strings.Contains(id, "#") {
		return errors.New("client_id is not a valid URL")
	}
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && f.allowInsecure && (isLoopbackRedirectHost(u.Hostname()) || isLoopbackIP(u.Hostname())):
	default:
		return errors.New("client_id URL must use https")
	}
	if u.Path == "" || u.Path == "/" {
		return errors.New("client_id URL must have a path")
	}
	for _, seg := range strings.Split(u.Path, "/") {
		if seg == "." || seg == ".." {
			return errors.New("client_id URL must not contain dot segments")
		}
	}
	return nil
}

// get returns the client described by the metadata document at id.
func (f *cimdFetcher) get(ctx context.Context, id string) (*client, error) {
	if err := f.validateClientIDURL(id); err != nil {
		return nil, err
	}
	now := time.Now()
	f.mu.Lock()
	if e, ok := f.cache[id]; ok && now.Before(e.expires) {
		f.mu.Unlock()
		return e.client, e.err
	}
	f.mu.Unlock()

	c, err := f.fetch(ctx, id)
	if err != nil && ctx.Err() != nil {
		return nil, err // don't cache cancellations
	}
	ttl := cimdCacheTTL
	if err != nil {
		ttl = cimdNegativeTTL
	}
	f.mu.Lock()
	if len(f.cache) >= cimdMaxEntries {
		for k, e := range f.cache {
			if !now.Before(e.expires) {
				delete(f.cache, k)
			}
		}
		if len(f.cache) >= cimdMaxEntries {
			clear(f.cache)
		}
	}
	f.cache[id] = cimdEntry{client: c, err: err, expires: now.Add(ttl)}
	f.mu.Unlock()
	return c, err
}

// cimdDocument is the subset of client metadata dbgateway uses.
type cimdDocument struct {
	ClientID                string   `json:"client_id"`
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	ClientSecret            string   `json:"client_secret"`
}

func (f *cimdFetcher) fetch(ctx context.Context, id string) (*client, error) {
	ctx, cancel := context.WithTimeout(ctx, cimdTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, id, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch client metadata: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch client metadata: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, cimdMaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read client metadata: %w", err)
	}
	if len(body) > cimdMaxBytes {
		return nil, errors.New("client metadata document is too large")
	}
	var doc cimdDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("parse client metadata: %w", err)
	}
	if doc.ClientID != id {
		return nil, errors.New("client metadata client_id does not match its URL")
	}
	if doc.ClientSecret != "" {
		return nil, errors.New("client metadata must not contain a client_secret")
	}
	if m := doc.TokenEndpointAuthMethod; m != "" && m != "none" {
		return nil, fmt.Errorf("unsupported token_endpoint_auth_method %q (only none)", m)
	}
	if len(doc.RedirectURIs) == 0 || len(doc.RedirectURIs) > cimdMaxRedirect {
		return nil, errors.New("client metadata must list 1-20 redirect_uris")
	}
	for _, u := range doc.RedirectURIs {
		if !validRedirectURI(u) {
			return nil, fmt.Errorf("client metadata has an invalid redirect_uri %q", u)
		}
	}
	name := strings.TrimSpace(doc.ClientName)
	if name == "" {
		name = id
	}
	return &client{ID: id, Name: truncate(name, 100), RedirectURIs: doc.RedirectURIs, Kind: clientCIMD}, nil
}

// truncate shortens s to at most n runes.
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}
