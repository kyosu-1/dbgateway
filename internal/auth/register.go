package auth

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"

	"github.com/kyosu-1/dbgateway/internal/store"
)

const (
	maxRegisterBytes    = 16 << 10
	maxRedirectURIs     = 10
	maxRegisteredClient = 10000
)

// registerRequest is the subset of RFC 7591 client metadata we accept.
type registerRequest struct {
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	Scope                   string   `json:"scope"`
}

type registerResponse struct {
	ClientID                string   `json:"client_id"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
}

func registerError(w http.ResponseWriter, code, desc string) {
	writeOAuthError(w, http.StatusBadRequest, code, desc)
}

// handleRegister is RFC 7591 Dynamic Client Registration, kept as a
// fallback for clients without Client ID Metadata Document support. Only
// public clients are registered; names are self-reported.
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRegisterBytes)
	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		registerError(w, "invalid_client_metadata", "malformed JSON body")
		return
	}
	if m := req.TokenEndpointAuthMethod; m != "" && m != "none" {
		registerError(w, "invalid_client_metadata", "only token_endpoint_auth_method=none is supported")
		return
	}
	if len(req.RedirectURIs) == 0 || len(req.RedirectURIs) > maxRedirectURIs {
		registerError(w, "invalid_redirect_uri", "1 to 10 redirect_uris are required")
		return
	}
	for _, u := range req.RedirectURIs {
		if !validRedirectURI(u) {
			registerError(w, "invalid_redirect_uri", "redirect_uris must be https or http on a loopback address")
			return
		}
	}
	for _, g := range req.GrantTypes {
		if g != "authorization_code" && g != "refresh_token" {
			registerError(w, "invalid_client_metadata", "unsupported grant_type "+g)
			return
		}
	}
	for _, rt := range req.ResponseTypes {
		if rt != "code" {
			registerError(w, "invalid_client_metadata", "unsupported response_type "+rt)
			return
		}
	}
	name := truncate(strings.TrimSpace(req.ClientName), 100)
	if name == "" {
		name = "Unnamed client"
	}
	n, err := s.store.CountClients(r.Context())
	if err != nil {
		s.log.Error("auth: count clients", "err", err)
		errServer(w)
		return
	}
	if n >= maxRegisteredClient {
		writeOAuthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "client registration limit reached")
		return
	}
	now := s.now()
	c := &store.Client{ClientID: newID("dcr_"), ClientName: name, RedirectURIs: slices.Clone(req.RedirectURIs), CreatedAt: now}
	if err := s.store.CreateClient(r.Context(), c); err != nil {
		s.log.Error("auth: create client", "err", err)
		errServer(w)
		return
	}
	s.log.Info("auth: client registered", "client_id", c.ClientID, "client_name", name)
	writeJSON(w, http.StatusCreated, registerResponse{
		ClientID:                c.ClientID,
		ClientIDIssuedAt:        now.Unix(),
		ClientName:              name,
		RedirectURIs:            c.RedirectURIs,
		TokenEndpointAuthMethod: "none",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
	})
}
