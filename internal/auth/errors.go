package auth

import (
	"encoding/json"
	"net/http"
)

// writeJSON writes an uncacheable JSON response.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeOAuthError writes an RFC 6749 §5.2 error response.
func writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Basic realm="dbgateway"`)
	}
	writeJSON(w, status, map[string]string{"error": code, "error_description": description})
}

// errInvalidGrant and friends are shorthands for the token endpoint.
func errInvalidRequest(w http.ResponseWriter, desc string) {
	writeOAuthError(w, http.StatusBadRequest, "invalid_request", desc)
}

func errInvalidGrant(w http.ResponseWriter, desc string) {
	writeOAuthError(w, http.StatusBadRequest, "invalid_grant", desc)
}

func errInvalidClient(w http.ResponseWriter, desc string) {
	writeOAuthError(w, http.StatusUnauthorized, "invalid_client", desc)
}

func errServer(w http.ResponseWriter) {
	writeOAuthError(w, http.StatusInternalServerError, "server_error", "internal error")
}
