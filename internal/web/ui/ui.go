// Package ui is the page rendering foundation shared by every server-side
// HTML page of dbgateway: the base layout (app header with navigation, or
// a centered card), the stylesheet and scripts served from /static, the
// i18n template functions, security headers and the page wrapper.
//
// Pages are html/template files named templates/<name>.html that define a
// "content" template. Each package adds its own pages to the shared
// Renderer with Add, and renders them with Render:
//
//	rd.Add(templateFS, ui.LayoutApp, "approvals", "approval")
//	rd.Render(w, r, ui.Page{Name: "approvals", Title: "title.approvals", User: email, Active: "approvals", Data: data})
//
// Every user-facing string is a message key of internal/web/i18n,
// translated in the template with {{t "key" args...}}. The app header shows
// the navigation returned by the NavFunc set with SetNav, so that it only
// lists what the user may use.
package ui

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/kyosu-1/dbgateway/internal/web/i18n"
)

//go:embed templates/base.html
var baseFS embed.FS

//go:embed static
var staticFS embed.FS

// Layout is the frame around a page.
type Layout string

const (
	// LayoutCard centers the page in a card (login, consent, messages).
	LayoutCard Layout = "card"
	// LayoutApp shows the app header with navigation.
	LayoutApp Layout = "app"
)

// Width of the main column of app pages.
const (
	WidthDefault = ""       // 800px: detail pages, account
	WidthWide    = "wide"   // 1120px: lists
	WidthNarrow  = "narrow" // 640px: forms
	WidthFull    = "full"   // 1360px: SQL console
)

// MaxFormBytes bounds request bodies of pages.
const MaxFormBytes = 64 << 10

// NavItem is one entry of the app header navigation.
type NavItem struct {
	Key   string // matches Page.Active
	Label string // message key
	Href  string
	Badge int // shown when > 0 (e.g. pending approvals)
}

// NavFunc returns the navigation for the logged-in user (only what they may
// use). It must be cheap and must not fail: on errors it should leave the
// affected items out.
type NavFunc func(r *http.Request, email string) []NavItem

// Page describes one rendering.
type Page struct {
	Name   string // template name (templates/<name>.html)
	Title  string // message key of the <title>
	Status int    // HTTP status (default 200)
	// User is the logged-in e-mail. App pages show it in the header.
	User string
	// Active is the navigation key of the current section ("account" for
	// the account page).
	Active string
	Width  string
	// Scripts are same-origin script URLs (inline scripts are blocked by
	// the CSP), e.g. "/static/webauthn.js".
	Scripts []string
	// HideDevBanner hides the dev-login banner (the login page shows its
	// own warning).
	HideDevBanner bool
	Data          map[string]any
}

// Options configure a Renderer.
type Options struct {
	// DevMode shows the dev-login warning banner on every page.
	DevMode bool
	Logger  *slog.Logger
	// Catalog defaults to i18n.Default().
	Catalog *i18n.Catalog
}

// Renderer renders pages. It is safe for concurrent use once pages are
// added (Add and SetNav are called during setup).
type Renderer struct {
	devMode bool
	log     *slog.Logger
	i18n    *i18n.Catalog

	mu      sync.RWMutex
	pages   map[string]*template.Template
	layouts map[string]Layout
	nav     NavFunc
}

// New returns a Renderer without pages.
func New(opts Options) *Renderer {
	rd := &Renderer{devMode: opts.DevMode, log: opts.Logger, i18n: opts.Catalog,
		pages: map[string]*template.Template{}, layouts: map[string]Layout{}}
	if rd.log == nil {
		rd.log = slog.Default()
	}
	if rd.i18n == nil {
		rd.i18n = i18n.Default()
	}
	return rd
}

// Catalog returns the message catalog.
func (rd *Renderer) Catalog() *i18n.Catalog { return rd.i18n }

// Printer returns the message printer for the request's language, for
// strings composed in Go.
func (rd *Renderer) Printer(r *http.Request) *i18n.Printer {
	return rd.i18n.Printer(rd.i18n.Negotiate(r))
}

// Add parses pages from fsys (templates/<name>.html, each defining
// "content") together with the base layout. Page names are global.
func (rd *Renderer) Add(fsys fs.FS, layout Layout, names ...string) error {
	rd.mu.Lock()
	defer rd.mu.Unlock()
	for _, name := range names {
		if _, dup := rd.pages[name]; dup {
			return fmt.Errorf("ui: page %q added twice", name)
		}
		t, err := template.New(name).Funcs(i18n.FuncStubs()).Funcs(Funcs()).ParseFS(baseFS, "templates/base.html")
		if err != nil {
			return fmt.Errorf("ui: parse base: %w", err)
		}
		if t, err = t.ParseFS(fsys, "templates/"+name+".html"); err != nil {
			return fmt.Errorf("ui: parse template %s: %w", name, err)
		}
		rd.pages[name] = t
		rd.layouts[name] = layout
	}
	return nil
}

// SetNav sets the navigation provider of the app header.
func (rd *Renderer) SetNav(f NavFunc) {
	rd.mu.Lock()
	defer rd.mu.Unlock()
	rd.nav = f
}

// navLink is a NavItem prepared for the template.
type navLink struct {
	NavItem
	Current bool
}

// pageData is the root object of the base template.
type pageData struct {
	Title    string
	Layout   Layout
	Width    string
	DevMode  bool
	SwitchJa string
	SwitchEn string
	User     string
	Initials string
	Active   string
	Nav      []navLink
	Scripts  []string
	Data     map[string]any
}

// Render executes a page in the request's language. The page is rendered
// into a buffer first, so a template error never produces a half-written
// page.
func (rd *Renderer) Render(w http.ResponseWriter, r *http.Request, p Page) {
	rd.mu.RLock()
	base, ok := rd.pages[p.Name]
	layout := rd.layouts[p.Name]
	navf := rd.nav
	rd.mu.RUnlock()
	if !ok {
		rd.log.Error("ui: unknown page", "page", p.Name)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	t, err := base.Clone()
	if err != nil {
		rd.log.Error("ui: clone template", "page", p.Name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	t.Funcs(rd.Printer(r).FuncMap())
	d := pageData{
		Title: p.Title, Layout: layout, Width: p.Width, DevMode: rd.devMode && !p.HideDevBanner,
		SwitchJa: i18n.SwitchURL(r, "ja", "/account"), SwitchEn: i18n.SwitchURL(r, "en", "/account"),
		User: p.User, Initials: Initials(p.User), Active: p.Active, Scripts: p.Scripts, Data: p.Data,
	}
	if layout == LayoutApp && p.User != "" && navf != nil {
		for _, it := range navf(r, p.User) {
			d.Nav = append(d.Nav, navLink{NavItem: it, Current: it.Key == p.Active})
		}
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "base", d); err != nil {
		rd.log.Error("ui: render page", "page", p.Name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	status := p.Status
	if status == 0 {
		status = http.StatusOK
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Vary", "Cookie, Accept-Language")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

// SecurityHeaders sets headers that every response should carry. The CSP
// allows same-origin resources only: no inline scripts or styles.
func SecurityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		// No form-action: the consent form legitimately redirects to the
		// client's redirect_uri.
		hd.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'")
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("Referrer-Policy", "no-referrer")
		h.ServeHTTP(w, r)
	})
}

// Wrap wraps an HTML page handler: security headers, no caching, the
// ?lang= switch and a bounded request body.
func (rd *Renderer) Wrap(h http.HandlerFunc) http.Handler {
	return SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if rd.i18n.SwitchLanguage(w, r) {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, MaxFormBytes)
		h(w, r)
	}))
}

// staticFiles maps served paths to embedded files and content types.
var staticFiles = map[string]string{
	"/static/dbgw.css":    "text/css; charset=utf-8",
	"/static/webauthn.js": "text/javascript; charset=utf-8",
	"/static/copy.js":     "text/javascript; charset=utf-8",
}

// RegisterStatic serves the stylesheet and scripts.
func RegisterStatic(mux *http.ServeMux) {
	for path, ctype := range staticFiles {
		body, err := staticFS.ReadFile(strings.TrimPrefix(path, "/"))
		if err != nil {
			panic(err) // embedded; cannot happen
		}
		mux.Handle("GET "+path, SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", ctype)
			w.Header().Set("Cache-Control", "public, max-age=3600")
			_, _ = w.Write(body)
		})))
	}
}

// Initials returns up to two upper-case letters of an e-mail's local part
// (for avatars).
func Initials(email string) string {
	local, _, _ := strings.Cut(email, "@")
	r := []rune(strings.ToUpper(local))
	if len(r) > 2 {
		r = r[:2]
	}
	return string(r)
}

// Funcs returns the language-independent template functions available to
// every page (in addition to the i18n functions t, fmtTime, fmtDuration and
// lang).
func Funcs() template.FuncMap {
	return template.FuncMap{
		"initials": Initials,
		"inc":      func(i int) int { return i + 1 },
		"join":     strings.Join,
		"has":      func(list []string, v string) bool { return slices.Contains(list, v) },
		"avatar":   AvatarTone,
		"dict":     dict,
		"deref64": func(n *int64) int64 {
			if n == nil {
				return 0
			}
			return *n
		},
		"deref": func(t *time.Time) time.Time {
			if t == nil {
				return time.Time{}
			}
			return *t
		},
	}
}

// dict builds a map from alternating keys and values (for passing several
// values to a sub-template).
func dict(kv ...any) map[string]any {
	m := make(map[string]any, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		k, _ := kv[i].(string)
		m[k] = kv[i+1]
	}
	return m
}

// AvatarTone picks one of a few avatar colors from an e-mail (stable).
func AvatarTone(email string) string {
	var h uint32
	for _, c := range strings.ToLower(email) {
		h = h*31 + uint32(c)
	}
	return []string{"green", "blue", "orange", "purple"}[h%4]
}
