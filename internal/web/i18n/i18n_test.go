package i18n

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"testing"
	"time"
)

var verbRe = regexp.MustCompile(`%[a-z]`)

func TestCatalogsComplete(t *testing.T) {
	c := Default()
	base := c.Keys(c.Languages()[0])
	if len(base) == 0 {
		t.Fatal("empty catalog")
	}
	for _, lang := range c.Languages() {
		keys := c.Keys(lang)
		for _, k := range base {
			if !slices.Contains(keys, k) {
				t.Errorf("%s: missing %q", lang, k)
			}
		}
		for _, k := range keys {
			if !slices.Contains(base, k) {
				t.Errorf("%s: extra key %q not in %s", lang, k, c.Languages()[0])
			}
		}
		// Placeholders must agree so that arguments line up.
		for _, k := range base {
			want := verbRe.FindAllString(c.msgs[c.Languages()[0]][k], -1)
			got := verbRe.FindAllString(c.msgs[lang][k], -1)
			if !slices.Equal(want, got) {
				t.Errorf("%s: %q placeholders %v, want %v", lang, k, got, want)
			}
		}
	}
}

func TestMatch(t *testing.T) {
	c := Default()
	for header, want := range map[string]string{
		"":                        "en",
		"ja":                      "ja",
		"ja-JP,ja;q=0.9,en;q=0.8": "ja",
		"en-US,en;q=0.9":          "en",
		"fr-FR,ja;q=0.5":          "ja",
		"de":                      "en",
		"garbage;;;":              "en",
	} {
		if got := c.Match(header); got != want {
			t.Errorf("Match(%q) = %q, want %q", header, got, want)
		}
	}
}

func TestNegotiateCookieWins(t *testing.T) {
	c := Default()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Accept-Language", "ja")
	r.AddCookie(&http.Cookie{Name: CookieName, Value: "en"})
	if got := c.Negotiate(r); got != "en" {
		t.Fatalf("Negotiate = %q", got)
	}
	r = httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: CookieName, Value: "xx"})
	r.Header.Set("Accept-Language", "ja")
	if got := c.Negotiate(r); got != "ja" {
		t.Fatalf("Negotiate with bad cookie = %q", got)
	}
}

func TestSwitchLanguage(t *testing.T) {
	c := Default()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/authorize?client_id=x&lang=ja", nil)
	if !c.SwitchLanguage(w, r) {
		t.Fatal("not handled")
	}
	if loc := w.Header().Get("Location"); loc != "/authorize?client_id=x" {
		t.Fatalf("Location = %q", loc)
	}
	if ck := w.Result().Cookies(); len(ck) != 1 || ck[0].Value != "ja" {
		t.Fatalf("cookies = %v", ck)
	}
	if c.SwitchLanguage(httptest.NewRecorder(), httptest.NewRequest("GET", "/x", nil)) {
		t.Fatal("handled without param")
	}
	if got := SwitchURL(httptest.NewRequest("POST", "/device", nil), "en", "/account"); got != "/account?lang=en" {
		t.Fatalf("SwitchURL(POST) = %q", got)
	}
}

func TestPrinter(t *testing.T) {
	c := Default()
	ja, en := c.Printer("ja"), c.Printer("en")
	if got := ja.T("consent.db_read", "prod"); got != "prod の読み取り" {
		t.Errorf("ja = %q", got)
	}
	if got := en.T("no.such.key"); got != "no.such.key" {
		t.Errorf("missing = %q", got)
	}
	if got := c.Printer("fr").Lang(); got != "en" {
		t.Errorf("fallback lang = %q", got)
	}
	for d, want := range map[time.Duration]string{time.Hour: "1時間", 90 * time.Minute: "1時間30分", 7 * 24 * time.Hour: "7日"} {
		if got := ja.Duration(d); got != want {
			t.Errorf("ja.Duration(%v) = %q", d, got)
		}
	}
	if got := ja.Duration(10 * time.Second); got != "10秒" {
		t.Errorf("ja.Duration(10s) = %q", got)
	}
	if got := en.Duration(90 * time.Minute); got != "1 hour 30 minutes" {
		t.Errorf("en.Duration = %q", got)
	}
}
