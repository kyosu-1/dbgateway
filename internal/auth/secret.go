package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"

	"github.com/kyosu-1/dbgateway/internal/store"
)

// randomToken returns n random bytes, base64url-encoded without padding.
func randomToken(n int) string {
	b := make([]byte, n)
	// crypto/rand.Read never returns an error on supported platforms and
	// crashes the program otherwise.
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// newSecret returns a new prefixed 256-bit secret and its storage hash.
func newSecret(prefix string) (raw, hash string) {
	raw = prefix + randomToken(32)
	return raw, store.HashSecret(raw)
}

// newID returns a non-secret random identifier.
func newID(prefix string) string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

// derive returns a value derived from a secret for a given purpose. It is
// used to bind CSRF tokens, OIDC state, nonce and PKCE verifier to a secret
// that only lives in an HttpOnly cookie. The stored session hash
// (SHA-256 of the raw value) never equals a derived value.
func derive(purpose, secret string) string {
	sum := sha256.Sum256([]byte("dbgw:" + purpose + ":" + secret))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// secureEqual compares two strings in constant time.
func secureEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// s256 computes the PKCE S256 code challenge of a verifier.
func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
