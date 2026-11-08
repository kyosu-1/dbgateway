package auth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/kyosu-1/dbgateway/internal/store"
)

// clientKind says where a client's metadata comes from.
type clientKind int

const (
	clientBuiltin clientKind = iota // dbgw-cli
	clientCIMD                      // Client ID Metadata Document (verified by URL)
	clientDCR                       // dynamically registered (self-reported)
)

// client is a resolved OAuth client. All clients are public.
type client struct {
	ID           string
	Name         string
	RedirectURIs []string
	Kind         clientKind
}

var errUnknownClient = errors.New("unknown client")

// resolveClient finds a client by client_id: an https URL is a Client ID
// Metadata Document; anything else must have been registered via DCR.
func (s *Server) resolveClient(ctx context.Context, id string) (*client, error) {
	switch {
	case id == "" || len(id) > 2048:
		return nil, errUnknownClient
	case id == CLIClientID:
		return &client{ID: id, Name: CLIClientName, Kind: clientBuiltin}, nil
	case strings.HasPrefix(id, "https://") || strings.HasPrefix(id, "http://"):
		return s.cimd.get(ctx, id)
	}
	c, err := s.store.GetClient(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errUnknownClient
	}
	if err != nil {
		return nil, fmt.Errorf("auth: load client: %w", err)
	}
	return &client{ID: c.ClientID, Name: c.ClientName, RedirectURIs: c.RedirectURIs, Kind: clientDCR}, nil
}

// allowsRedirect reports whether uri is one of the client's registered
// redirect URIs.
func (c *client) allowsRedirect(uri string) bool {
	if uri == "" {
		return false
	}
	for _, reg := range c.RedirectURIs {
		if redirectMatches(reg, uri) {
			return true
		}
	}
	return false
}

// redirectMatches compares redirect URIs exactly, except that for loopback
// redirect URIs any port is accepted (RFC 8252 §7.3).
func redirectMatches(registered, requested string) bool {
	if registered == requested {
		return true
	}
	ru, err1 := url.Parse(registered)
	qu, err2 := url.Parse(requested)
	if err1 != nil || err2 != nil {
		return false
	}
	if ru.Scheme != "http" || qu.Scheme != "http" || !isLoopbackRedirectHost(ru.Hostname()) {
		return false
	}
	return ru.Hostname() == qu.Hostname() &&
		ru.EscapedPath() == qu.EscapedPath() &&
		ru.RawQuery == qu.RawQuery &&
		qu.User == nil && qu.Fragment == "" && validPort(qu.Port())
}

func validPort(p string) bool {
	if p == "" {
		return true
	}
	for _, c := range p {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(p) <= 5
}

func isLoopbackRedirectHost(h string) bool {
	return h == "127.0.0.1" || h == "::1" || h == "localhost"
}

// validRedirectURI reports whether uri is acceptable for registration:
// https, or http on a loopback host. Fragments and credentials are refused.
func validRedirectURI(uri string) bool {
	if len(uri) > 2000 {
		return false
	}
	u, err := url.Parse(uri)
	if err != nil || u.Host == "" || u.Fragment != "" || u.User != nil || strings.ContainsAny(uri, " \t\r\n") {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		return isLoopbackRedirectHost(u.Hostname()) || isLoopbackIP(u.Hostname())
	}
	return false
}

func isLoopbackIP(h string) bool {
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}
