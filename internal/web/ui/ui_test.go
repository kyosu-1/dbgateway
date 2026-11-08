package ui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func TestHighlightSQL(t *testing.T) {
	sql := "UPDATE users SET plan = 'it''s', n = 42 /* note */ WHERE id = $1 AND x = ? -- end\n RETURNING $$a$$"
	toks := HighlightSQL(sql)
	var b strings.Builder
	classes := map[string][]string{}
	for _, tk := range toks {
		b.WriteString(tk.Text)
		classes[tk.Class] = append(classes[tk.Class], strings.TrimSpace(tk.Text))
	}
	if b.String() != sql {
		t.Fatalf("tokens do not round-trip: %q", b.String())
	}
	for class, want := range map[string]string{"str": "'it''s'", "num": "42", "param": "$1", "comment": "/* note */"} {
		if !strings.Contains(strings.Join(classes[class], "|"), want) {
			t.Errorf("%s tokens %v, want %q", class, classes[class], want)
		}
	}
	if !strings.Contains(strings.Join(classes["kw"], "|"), "UPDATE") {
		t.Errorf("keywords: %v", classes["kw"])
	}
}

func TestInertText(t *testing.T) {
	if got := InertText("ok ‮evil⁦ ​x"); got != "ok �evil� �x" {
		t.Fatalf("InertText = %q", got)
	}
	if got := InertText("plain 日本語"); got != "plain 日本語" {
		t.Fatalf("InertText changed plain text: %q", got)
	}
}

func TestRenderNavAndHeaders(t *testing.T) {
	rd := New(Options{})
	fsys := fstest.MapFS{"templates/page.html": {Data: []byte(`{{define "content"}}<p>{{.Msg}}</p>{{end}}`)}}
	if err := rd.Add(fsys, LayoutApp, "page"); err != nil {
		t.Fatal(err)
	}
	if err := rd.Add(fsys, LayoutApp, "page"); err == nil {
		t.Fatal("duplicate page accepted")
	}
	rd.SetNav(func(*http.Request, string) []NavItem {
		return []NavItem{{Key: "approvals", Label: "nav.approvals", Href: "/approvals", Badge: 3}, {Key: "console", Label: "nav.console", Href: "/console"}}
	})
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/approvals", nil)
	r.Header.Set("Accept-Language", "ja")
	rd.Wrap(func(w http.ResponseWriter, r *http.Request) {
		rd.Render(w, r, Page{Name: "page", Title: "title.approvals", User: "hanako@example.com", Active: "approvals",
			Data: map[string]any{"Msg": "<b>x</b>"}})
	}).ServeHTTP(w, r)
	body := w.Body.String()
	for _, want := range []string{
		`<html lang="ja">`, `<a class="nav-link" href="/approvals" aria-current="page">承認<span class="nav-badge" aria-hidden="true">3</span>`,
		`href="/console">SQLエディタ</a>`, ">HA</a>", "&lt;b&gt;x&lt;/b&gt;",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in\n%s", want, body)
		}
	}
	h := w.Header()
	if h.Get("Content-Security-Policy") != "default-src 'self'; frame-ancestors 'none'; base-uri 'none'" || h.Get("Cache-Control") != "no-store" {
		t.Errorf("headers: %v", h)
	}
}

func TestStatic(t *testing.T) {
	mux := http.NewServeMux()
	RegisterStatic(mux)
	for path, ctype := range staticFiles {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 200 || w.Header().Get("Content-Type") != ctype || w.Body.Len() == 0 {
			t.Errorf("%s: %d %q", path, w.Code, w.Header().Get("Content-Type"))
		}
	}
}
