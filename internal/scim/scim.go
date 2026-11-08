// Package scim implements the SCIM 2.0 provisioning endpoint (RFC 7643 and
// RFC 7644) used by IdPs such as Okta and Microsoft Entra ID to push users
// and groups into dbgateway.
//
// Scope: the subset that Okta and Entra ID provisioning use. /Users and
// /Groups support create, read, list with simple "eq" filters and
// pagination, replace (PUT), PATCH and delete; /ServiceProviderConfig,
// /ResourceTypes and /Schemas describe that subset. Bulk, sorting, ETags,
// /Me and password changes are not supported.
//
// A SCIM user is tied to a dbgateway user by email: the primary email (or
// the "work" email, or the first one), falling back to userName when it is
// an email address. It must equal the email claim of the OIDC login. Group
// display names feed the IdP groups list used by RBAC, so they map to
// dbgateway groups through groups[].oidc_group, exactly like OIDC groups.
// See internal/store (sqlite_scim.go) for the persistence rules
// (deactivation revokes tokens and sessions; SCIM groups replace the login
// snapshot).
package scim

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/store"
)

// PathPrefix is where the handler is mounted. The handler expects the full
// request path (mount it with mux.Handle(PathPrefix+"/", h), without
// http.StripPrefix).
const PathPrefix = "/scim/v2"

// ContentType is the media type of every SCIM response.
const ContentType = "application/scim+json"

// maxBodyBytes bounds request bodies.
const maxBodyBytes = 1 << 20

// Paging defaults (RFC 7644 §3.4.2.4).
const (
	defaultCount = 100
	maxCount     = 200
)

// Store is the persistence the SCIM endpoint needs. *store.SQLite
// implements it.
type Store interface {
	CreateSCIMUser(ctx context.Context, u *store.SCIMUser, now time.Time) error
	GetSCIMUser(ctx context.Context, id string) (*store.SCIMUser, error)
	ListSCIMUsers(ctx context.Context, f store.SCIMUserFilter, offset, limit int) ([]*store.SCIMUser, int, error)
	UpdateSCIMUser(ctx context.Context, id string, now time.Time, fn func(*store.SCIMUser) error) (*store.SCIMUser, error)
	DeleteSCIMUser(ctx context.Context, id string, now time.Time) error

	CreateSCIMGroup(ctx context.Context, g *store.SCIMGroup, now time.Time) error
	GetSCIMGroup(ctx context.Context, id string, withMembers bool) (*store.SCIMGroup, error)
	ListSCIMGroups(ctx context.Context, f store.SCIMGroupFilter, offset, limit int, withMembers bool) ([]*store.SCIMGroup, int, error)
	UpdateSCIMGroup(ctx context.Context, id string, now time.Time, fn func(*store.SCIMGroup) error) (*store.SCIMGroup, error)
	DeleteSCIMGroup(ctx context.Context, id string, now time.Time) error
}

var _ Store = (*store.SQLite)(nil)

// Options configures the handler.
type Options struct {
	Config *config.Config
	Store  Store
	// Logger defaults to slog.Default().
	Logger *slog.Logger
	// Now defaults to time.Now.
	Now func() time.Time
}

type handler struct {
	enabled   bool
	tokenHash [sha256.Size]byte
	hasToken  bool
	base      string // public URL of the SCIM root, for meta.location
	store     Store
	log       *slog.Logger
	now       func() time.Time
}

// NewHandler returns the SCIM endpoint. When SCIM is disabled (or no
// configuration is given) every request gets 404. The bearer token is read
// once, from the environment variable named by scim.token_env; if it is
// empty every request is rejected.
func NewHandler(opts Options) http.Handler {
	h := &handler{store: opts.Store, log: opts.Logger, now: opts.Now}
	if h.log == nil {
		h.log = slog.Default()
	}
	if h.now == nil {
		h.now = time.Now
	}
	cfg := opts.Config
	if cfg == nil || !cfg.SCIM.Enabled || opts.Store == nil {
		return h
	}
	h.enabled = true
	h.base = strings.TrimRight(cfg.Server.PublicURL, "/") + PathPrefix
	if tok := os.Getenv(cfg.SCIM.TokenEnv); tok != "" {
		h.tokenHash, h.hasToken = sha256.Sum256([]byte(tok)), true
	} else {
		h.log.Error("scim: bearer token is not set; rejecting every SCIM request", "env", cfg.SCIM.TokenEnv)
	}
	return h
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.enabled {
		http.NotFound(w, r)
		return
	}
	if !h.authorized(r) {
		h.log.Warn("scim: unauthorized request", "remote", r.RemoteAddr, "method", r.Method, "path", r.URL.Path)
		w.Header().Set("WWW-Authenticate", `Bearer realm="dbgateway-scim"`)
		writeError(w, &Error{Status: http.StatusUnauthorized, Detail: "missing or invalid bearer token"})
		return
	}
	rest, ok := strings.CutPrefix(r.URL.Path, PathPrefix)
	if !ok {
		writeError(w, errNotFound("unknown endpoint"))
		return
	}
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) > 2 || parts[0] == "" {
		writeError(w, errNotFound("unknown endpoint"))
		return
	}
	id := ""
	if len(parts) == 2 {
		id = parts[1]
	}
	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	}
	var err error
	switch parts[0] {
	case "Users":
		err = h.users(w, r, id)
	case "Groups":
		err = h.groups(w, r, id)
	case "ServiceProviderConfig":
		err = h.discovery(w, r, id, h.serviceProviderConfig)
	case "ResourceTypes":
		err = h.discovery(w, r, id, h.resourceTypes)
	case "Schemas":
		err = h.discovery(w, r, id, h.schemas)
	default:
		err = errNotFound("unknown endpoint")
	}
	if err != nil {
		h.fail(w, r, err)
	}
}

// authorized compares the bearer token in constant time (on hashes, so the
// length does not leak either).
func (h *handler) authorized(r *http.Request) bool {
	if !h.hasToken {
		return false
	}
	scheme, tok, ok := strings.Cut(strings.TrimSpace(r.Header.Get("Authorization")), " ")
	if !ok || !strings.EqualFold(scheme, "bearer") {
		return false
	}
	sum := sha256.Sum256([]byte(strings.TrimSpace(tok)))
	return subtle.ConstantTimeCompare(sum[:], h.tokenHash[:]) == 1
}

// fail writes err as a SCIM error, mapping store errors.
func (h *handler) fail(w http.ResponseWriter, r *http.Request, err error) {
	var se *Error
	var maxErr *http.MaxBytesError
	switch {
	case errors.As(err, &se):
	case errors.Is(err, store.ErrNotFound):
		se = errNotFound("resource not found")
	case errors.Is(err, store.ErrConflict):
		se = &Error{Status: http.StatusConflict, ScimType: "uniqueness", Detail: "a resource with the same userName, email or displayName already exists"}
	case errors.Is(err, store.ErrUnknownMember):
		se = badRequest("invalidValue", "%v", err)
	case errors.As(err, &maxErr):
		se = &Error{Status: http.StatusRequestEntityTooLarge, Detail: "request body too large"}
	default:
		h.log.Error("scim: internal error", "method", r.Method, "path", r.URL.Path, "err", err)
		se = &Error{Status: http.StatusInternalServerError, Detail: "internal error"}
	}
	writeError(w, se)
}

func (h *handler) discovery(w http.ResponseWriter, r *http.Request, id string, fn func(w http.ResponseWriter, id string) error) error {
	if r.Method != http.MethodGet {
		return errMethod()
	}
	return fn(w, id)
}

// Error is a SCIM error response (RFC 7644 §3.12).
type Error struct {
	Status   int
	ScimType string
	Detail   string
}

func (e *Error) Error() string {
	if e.ScimType != "" {
		return fmt.Sprintf("scim %d %s: %s", e.Status, e.ScimType, e.Detail)
	}
	return fmt.Sprintf("scim %d: %s", e.Status, e.Detail)
}

func badRequest(scimType, format string, args ...any) *Error {
	return &Error{Status: http.StatusBadRequest, ScimType: scimType, Detail: fmt.Sprintf(format, args...)}
}

func errNotFound(detail string) *Error {
	return &Error{Status: http.StatusNotFound, Detail: detail}
}

func errMethod() *Error {
	return &Error{Status: http.StatusMethodNotAllowed, Detail: "method not allowed"}
}

const (
	schemaError        = "urn:ietf:params:scim:api:messages:2.0:Error"
	schemaListResponse = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	schemaPatchOp      = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	schemaUser         = "urn:ietf:params:scim:schemas:core:2.0:User"
	schemaGroup        = "urn:ietf:params:scim:schemas:core:2.0:Group"
	schemaSPConfig     = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
	schemaResourceType = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
	schemaSchema       = "urn:ietf:params:scim:schemas:core:2.0:Schema"
)

func writeError(w http.ResponseWriter, e *Error) {
	body := map[string]any{
		"schemas": []string{schemaError},
		"status":  fmt.Sprint(e.Status),
		"detail":  e.Detail,
	}
	if e.ScimType != "" {
		body["scimType"] = e.ScimType
	}
	writeJSON(w, e.Status, body)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", ContentType+"; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

// decode reads a JSON request body into v.
func decode(r *http.Request, v any) error {
	if r.Body == nil {
		return badRequest("invalidSyntax", "request body required")
	}
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil {
		var maxErr *http.MaxBytesError
		var se *Error
		switch {
		case errors.As(err, &maxErr):
			return err
		case errors.As(err, &se):
			return se
		}
		return badRequest("invalidSyntax", "invalid JSON: %v", err)
	}
	if dec.More() {
		return badRequest("invalidSyntax", "unexpected data after the JSON body")
	}
	return nil
}

// newID returns a random UUID (version 4).
func newID() string {
	var b [16]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never fails
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	s := hex.EncodeToString(b[:])
	return s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:]
}

// listResponse is a SCIM ListResponse.
type listResponse struct {
	Schemas      []string `json:"schemas"`
	TotalResults int      `json:"totalResults"`
	StartIndex   int      `json:"startIndex"`
	ItemsPerPage int      `json:"itemsPerPage"`
	Resources    []any    `json:"Resources"`
}

// paging parses startIndex (1-based) and count.
func paging(r *http.Request) (startIndex, count int, err error) {
	startIndex, count = 1, defaultCount
	q := r.URL.Query()
	if v := q.Get("startIndex"); v != "" {
		var e error
		if startIndex, e = strconv.Atoi(v); e != nil {
			return 0, 0, badRequest("invalidValue", "startIndex must be an integer")
		}
		startIndex = max(startIndex, 1)
	}
	if v := q.Get("count"); v != "" {
		var e error
		if count, e = strconv.Atoi(v); e != nil {
			return 0, 0, badRequest("invalidValue", "count must be an integer")
		}
		count = min(max(count, 0), maxCount)
	}
	return startIndex, count, nil
}

// excludesMembers reports whether the request asks to leave out the
// members of groups (excludedAttributes=members, or an attributes list
// without members).
func excludesMembers(r *http.Request) bool {
	q := r.URL.Query()
	for _, a := range strings.Split(q.Get("excludedAttributes"), ",") {
		if strings.EqualFold(strings.TrimSpace(a), "members") {
			return true
		}
	}
	if attrs := q.Get("attributes"); attrs != "" {
		for _, a := range strings.Split(attrs, ",") {
			a = strings.ToLower(strings.TrimSpace(a))
			if a == "members" || strings.HasPrefix(a, "members.") {
				return false
			}
		}
		return true
	}
	return false
}

func timestamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }
