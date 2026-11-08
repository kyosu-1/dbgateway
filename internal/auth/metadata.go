package auth

import (
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/oauthex"

	"github.com/kyosu-1/dbgateway/internal/identity"
)

// asMetadata is the RFC 8414 authorization server metadata.
type asMetadata struct {
	Issuer                                 string   `json:"issuer"`
	AuthorizationEndpoint                  string   `json:"authorization_endpoint"`
	TokenEndpoint                          string   `json:"token_endpoint"`
	RegistrationEndpoint                   string   `json:"registration_endpoint"`
	DeviceAuthorizationEndpoint            string   `json:"device_authorization_endpoint"`
	RevocationEndpoint                     string   `json:"revocation_endpoint"`
	ScopesSupported                        []string `json:"scopes_supported"`
	ResponseTypesSupported                 []string `json:"response_types_supported"`
	ResponseModesSupported                 []string `json:"response_modes_supported"`
	GrantTypesSupported                    []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported          []string `json:"code_challenge_methods_supported"`
	TokenEndpointAuthMethodsSupported      []string `json:"token_endpoint_auth_methods_supported"`
	RevocationEndpointAuthMethodsSupported []string `json:"revocation_endpoint_auth_methods_supported"`
	ClientIDMetadataDocumentSupported      bool     `json:"client_id_metadata_document_supported"`
	AuthorizationResponseIssParameter      bool     `json:"authorization_response_iss_parameter_supported"`
}

func (s *Server) handleASMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, asMetadata{
		Issuer:                                 s.issuer,
		AuthorizationEndpoint:                  s.issuer + "/authorize",
		TokenEndpoint:                          s.issuer + "/token",
		RegistrationEndpoint:                   s.issuer + "/register",
		DeviceAuthorizationEndpoint:            s.issuer + "/device_authorization",
		RevocationEndpoint:                     s.issuer + "/revoke",
		ScopesSupported:                        s.scopesSupported(),
		ResponseTypesSupported:                 []string{"code"},
		ResponseModesSupported:                 []string{"query"},
		GrantTypesSupported:                    []string{"authorization_code", "refresh_token", GrantTypeDeviceCode},
		CodeChallengeMethodsSupported:          []string{"S256"},
		TokenEndpointAuthMethodsSupported:      []string{"none"},
		RevocationEndpointAuthMethodsSupported: []string{"none"},
		ClientIDMetadataDocumentSupported:      true,
		AuthorizationResponseIssParameter:      true,
	})
}

func (s *Server) handleProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, &oauthex.ProtectedResourceMetadata{
		Resource:               s.ResourceURL(),
		AuthorizationServers:   []string{s.issuer},
		ScopesSupported:        s.scopesSupported(),
		BearerMethodsSupported: []string{"header"},
		ResourceName:           "dbgateway",
	})
}

// scopesSupported lists db:read, plus db:write when approvals are enabled.
func (s *Server) scopesSupported() []string {
	if s.cfg.Approvals.Enabled {
		return []string{identity.ScopeRead, identity.ScopeWrite}
	}
	return []string{identity.ScopeRead}
}
