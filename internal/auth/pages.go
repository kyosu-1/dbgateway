package auth

import (
	"embed"
	"net/http"

	"github.com/kyosu-1/dbgateway/internal/web/ui"
)

//go:embed templates/*.html
var templateFS embed.FS

// addPages registers this package's pages with the renderer.
func addPages(rd *ui.Renderer) error {
	if err := rd.Add(templateFS, ui.LayoutCard, "consent", "login", "device", "message", "stepup", "enroll"); err != nil {
		return err
	}
	return rd.Add(templateFS, ui.LayoutApp, "account")
}

// render executes a card page in the request's language. titleKey and
// every user-facing string in data are message keys, translated by the
// template.
func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, name, titleKey string, data map[string]any) {
	p := ui.Page{Name: name, Title: titleKey, Status: status, Data: data, HideDevBanner: name == "login"}
	if name == "login" || name == "stepup" || name == "enroll" {
		p.Scripts = []string{"/static/webauthn.js"}
	}
	s.ui.Render(w, r, p)
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
