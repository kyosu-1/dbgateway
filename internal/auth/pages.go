package auth

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"net/http"

	"github.com/kyosu-1/dbgateway/internal/web/i18n"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static/dbgw.css
var stylesheet []byte

// pageLayouts maps each page to its layout: "card" (centered card) or
// "app" (header + content).
var pageLayouts = map[string]string{
	"consent": "card",
	"login":   "card",
	"device":  "card",
	"message": "card",
	"account": "app",
}

// parsePages parses every page with placeholder i18n functions. The
// parsed templates are never executed directly: render clones them and
// binds the request's language.
func parsePages() (map[string]*template.Template, error) {
	pages := map[string]*template.Template{}
	for name := range pageLayouts {
		t, err := template.New(name).Funcs(i18n.FuncStubs()).ParseFS(templateFS, "templates/base.html", "templates/"+name+".html")
		if err != nil {
			return nil, fmt.Errorf("auth: parse template %s: %w", name, err)
		}
		pages[name] = t
	}
	return pages, nil
}

type pageData struct {
	Title    string // message key
	Layout   string
	DevMode  bool
	SwitchJa string
	SwitchEn string
	Data     map[string]any
}

// render executes a page in the request's language. titleKey and every
// user-facing string in data are message keys, translated by the template.
// The page is rendered into a buffer first, so a template error never
// produces a half-written page.
func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, name, titleKey string, data map[string]any) {
	base, ok := s.pages[name]
	if !ok {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	t, err := base.Clone()
	if err != nil {
		s.log.Error("auth: clone template", "page", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	t.Funcs(s.i18n.Printer(s.i18n.Negotiate(r)).FuncMap())
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "base", pageData{
		Title:  titleKey,
		Layout: pageLayouts[name],
		// The login page carries its own dev-login warning.
		DevMode:  s.cfg.Auth.DevLogin && name != "login",
		SwitchJa: i18n.SwitchURL(r, "ja", "/account"),
		SwitchEn: i18n.SwitchURL(r, "en", "/account"),
		Data:     data,
	}); err != nil {
		s.log.Error("auth: render page", "page", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Vary", "Cookie, Accept-Language")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

// errorPage shows an error message (a message key).
func (s *Server) errorPage(w http.ResponseWriter, r *http.Request, status int, msgKey string) {
	s.render(w, r, status, "message", "title.error", map[string]any{
		"Tone": "error", "Heading": "error.heading", "Message": msgKey,
	})
}

// serverError logs err and shows a generic error page.
func (s *Server) serverError(w http.ResponseWriter, r *http.Request, err error) {
	s.log.Error("auth: internal error", "path", r.URL.Path, "err", err)
	s.errorPage(w, r, http.StatusInternalServerError, "error.internal")
}

func serveCSS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write(stylesheet)
}
