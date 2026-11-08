// Package webauthntest provides a virtual WebAuthn authenticator for tests
// and end-to-end checks: ES256, "none" attestation, user verification
// always performed, one discoverable credential.
package webauthntest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

// Authenticator is a virtual authenticator bound to one origin.
type Authenticator struct {
	origin string
	rpID   string
	key    *ecdsa.PrivateKey
	credID []byte
	user   []byte
	count  uint32
}

// New returns an authenticator for origin (e.g. "https://dbgw.example").
func New(origin string) (*Authenticator, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("webauthntest: invalid origin %q", origin)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	return &Authenticator{origin: origin, rpID: u.Hostname(), key: key, credID: id}, nil
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (a *Authenticator) clientData(typ, challenge string) []byte {
	b, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": a.origin, "crossOrigin": false})
	return b
}

func (a *Authenticator) authData(flags byte, attested []byte) []byte {
	rp := sha256.Sum256([]byte(a.rpID))
	a.count++
	var buf bytes.Buffer
	buf.Write(rp[:])
	buf.WriteByte(flags)
	_ = binary.Write(&buf, binary.BigEndian, a.count)
	buf.Write(attested)
	return buf.Bytes()
}

// Create answers navigator.credentials.create() options (JSON from the
// server) with an attestation response (JSON to post back).
func (a *Authenticator) Create(optsJSON []byte) ([]byte, error) {
	var opts struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
			RP        struct {
				ID string `json:"id"`
			} `json:"rp"`
			User struct {
				ID string `json:"id"`
			} `json:"user"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(optsJSON, &opts); err != nil {
		return nil, fmt.Errorf("webauthntest: creation options: %w", err)
	}
	pk := opts.PublicKey
	if pk.RP.ID != a.rpID {
		return nil, fmt.Errorf("webauthntest: relying party %q does not match origin host %q", pk.RP.ID, a.rpID)
	}
	a.user, _ = base64.RawURLEncoding.DecodeString(pk.User.ID)
	pub, err := a.key.PublicKey.Bytes() // uncompressed: 0x04 || X || Y
	if err != nil {
		return nil, err
	}
	cose, err := webauthncbor.Marshal(webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{KeyType: 2, Algorithm: -7},
		Curve:         1,
		XCoord:        pub[1:33],
		YCoord:        pub[33:65],
	})
	if err != nil {
		return nil, err
	}
	var attested bytes.Buffer
	attested.Write(make([]byte, 16)) // AAGUID
	_ = binary.Write(&attested, binary.BigEndian, uint16(len(a.credID)))
	attested.Write(a.credID)
	attested.Write(cose)
	att, err := webauthncbor.Marshal(struct {
		Fmt      string         `cbor:"fmt"`
		AttStmt  map[string]any `cbor:"attStmt"`
		AuthData []byte         `cbor:"authData"`
	}{"none", map[string]any{}, a.authData(0x45, attested.Bytes())}) // UP | UV | AT
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{
		"id": b64u(a.credID), "rawId": b64u(a.credID), "type": "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64u(a.clientData("webauthn.create", pk.Challenge)),
			"attestationObject": b64u(att),
			"transports":        []string{"internal"},
		},
		"clientExtensionResults": map[string]any{},
	})
}

// Get answers navigator.credentials.get() options with an assertion.
func (a *Authenticator) Get(optsJSON []byte) ([]byte, error) {
	var opts struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(optsJSON, &opts); err != nil {
		return nil, fmt.Errorf("webauthntest: request options: %w", err)
	}
	cd := a.clientData("webauthn.get", opts.PublicKey.Challenge)
	ad := a.authData(0x05, nil) // UP | UV
	cdHash := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, ad...), cdHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{
		"id": b64u(a.credID), "rawId": b64u(a.credID), "type": "public-key",
		"response": map[string]any{
			"clientDataJSON": b64u(cd), "authenticatorData": b64u(ad), "signature": b64u(sig), "userHandle": b64u(a.user),
		},
		"clientExtensionResults": map[string]any{},
	})
}
