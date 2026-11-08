// Package i18n is the message catalog of the dbgateway web UI.
//
// Messages live in embedded JSON files (messages/<lang>.json) keyed by
// message ID, with fmt-style placeholders. The language of a request is
// chosen from the "lang" cookie, then the Accept-Language header, then the
// fallback language (English). Templates use the functions returned by
// Printer.FuncMap:
//
//	{{t "consent.heading"}}  {{t "consent.logged_in_as" .Email}}
//	{{fmtTime .ExpiresAt}}   {{fmtDuration .TTL}}
package i18n

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"slices"
	"time"

	"golang.org/x/text/language"
)

// CookieName is the cookie holding the chosen language.
const CookieName = "lang"

// QueryParam is the query parameter that switches the language.
const QueryParam = "lang"

//go:embed messages/*.json
var messagesFS embed.FS

// Catalog holds the messages of every supported language.
type Catalog struct {
	langs   []string // supported languages; the first is the fallback
	msgs    map[string]map[string]string
	matcher language.Matcher
}

// New loads <lang>.json for each language from fsys. The first language is
// the fallback.
func New(fsys fs.FS, langs ...string) (*Catalog, error) {
	if len(langs) == 0 {
		return nil, fmt.Errorf("i18n: no languages")
	}
	c := &Catalog{langs: langs, msgs: map[string]map[string]string{}}
	tags := make([]language.Tag, len(langs))
	for i, l := range langs {
		tag, err := language.Parse(l)
		if err != nil {
			return nil, fmt.Errorf("i18n: language %q: %w", l, err)
		}
		tags[i] = tag
		raw, err := fs.ReadFile(fsys, l+".json")
		if err != nil {
			return nil, fmt.Errorf("i18n: %w", err)
		}
		m := map[string]string{}
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, fmt.Errorf("i18n: parse %s.json: %w", l, err)
		}
		c.msgs[l] = m
	}
	c.matcher = language.NewMatcher(tags)
	return c, nil
}

var defaultCatalog = func() *Catalog {
	sub, err := fs.Sub(messagesFS, "messages")
	if err != nil {
		panic(err)
	}
	c, err := New(sub, "en", "ja")
	if err != nil {
		panic(err)
	}
	return c
}()

// Default returns the built-in catalog (English and Japanese).
func Default() *Catalog { return defaultCatalog }

// Languages returns the supported languages; the first is the fallback.
func (c *Catalog) Languages() []string { return slices.Clone(c.langs) }

// Keys returns the sorted message IDs of a language.
func (c *Catalog) Keys(lang string) []string {
	var keys []string
	for k := range c.msgs[lang] {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// Supported reports whether lang is a supported language.
func (c *Catalog) Supported(lang string) bool { return slices.Contains(c.langs, lang) }

// Match picks the best supported language for an Accept-Language value.
func (c *Catalog) Match(acceptLanguage string) string {
	tags, _, err := language.ParseAcceptLanguage(acceptLanguage)
	if err != nil || len(tags) == 0 {
		return c.langs[0]
	}
	_, i, conf := c.matcher.Match(tags...)
	if conf == language.No {
		return c.langs[0]
	}
	return c.langs[i]
}

// Negotiate picks the language of a request: the lang cookie, then
// Accept-Language, then the fallback.
func (c *Catalog) Negotiate(r *http.Request) string {
	if ck, err := r.Cookie(CookieName); err == nil && c.Supported(ck.Value) {
		return ck.Value
	}
	return c.Match(r.Header.Get("Accept-Language"))
}

// SwitchLanguage handles "?lang=xx" on GET requests: it stores the
// language in a cookie and redirects to the same URL without the parameter.
// It reports whether it wrote a response.
func (c *Catalog) SwitchLanguage(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodGet || !r.URL.Query().Has(QueryParam) {
		return false
	}
	q := r.URL.Query()
	if lang := q.Get(QueryParam); c.Supported(lang) {
		http.SetCookie(w, &http.Cookie{
			Name:     CookieName,
			Value:    lang,
			Path:     "/",
			MaxAge:   365 * 24 * 60 * 60,
			HttpOnly: true,
			Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
			SameSite: http.SameSiteLaxMode,
		})
	}
	q.Del(QueryParam)
	u := url.URL{Path: r.URL.Path, RawQuery: q.Encode()}
	http.Redirect(w, r, u.String(), http.StatusSeeOther)
	return true
}

// SwitchURL returns a link that switches to lang and comes back to the
// current page. For non-GET requests it falls back to fallbackPath.
func SwitchURL(r *http.Request, lang, fallbackPath string) string {
	u := url.URL{Path: fallbackPath}
	if r.Method == http.MethodGet {
		u.Path = r.URL.Path
		q := r.URL.Query()
		q.Set(QueryParam, lang)
		u.RawQuery = q.Encode()
		return u.String()
	}
	u.RawQuery = url.Values{QueryParam: {lang}}.Encode()
	return u.String()
}

// Printer formats messages in one language.
type Printer struct {
	c    *Catalog
	lang string
}

// Printer returns a printer for lang (the fallback if unsupported).
func (c *Catalog) Printer(lang string) *Printer {
	if !c.Supported(lang) {
		lang = c.langs[0]
	}
	return &Printer{c: c, lang: lang}
}

// Lang returns the printer's language (for <html lang>).
func (p *Printer) Lang() string { return p.lang }

// T returns the message key formatted with args. A missing message falls
// back to the fallback language, then to the key itself.
func (p *Printer) T(key string, args ...any) string {
	msg, ok := p.c.msgs[p.lang][key]
	if !ok {
		if msg, ok = p.c.msgs[p.c.langs[0]][key]; !ok {
			return key
		}
	}
	if len(args) == 0 {
		return msg
	}
	return fmt.Sprintf(msg, args...)
}

// Time formats a date and time (in local time) using "format.datetime".
func (p *Printer) Time(t time.Time) string {
	return t.Local().Format(p.T("format.datetime"))
}

// Duration formats a duration in days, hours and minutes, e.g. "1時間30分"
// or "1 hour 30 minutes".
func (p *Printer) Duration(d time.Duration) string {
	d = d.Round(time.Minute)
	parts := []struct {
		n   int
		key string
	}{
		{int(d / (24 * time.Hour)), "duration.day"},
		{int(d % (24 * time.Hour) / time.Hour), "duration.hour"},
		{int(d % time.Hour / time.Minute), "duration.minute"},
	}
	var out string
	for _, part := range parts {
		if part.n == 0 {
			continue
		}
		key := part.key + ".other"
		if part.n == 1 {
			key = part.key + ".one"
		}
		if out != "" {
			out += p.T("duration.separator")
		}
		out += p.T(key, part.n)
	}
	if out == "" {
		out = p.T("duration.minute.other", 0)
	}
	return out
}

// FuncMap returns template functions bound to this printer: t, fmtTime,
// fmtDuration and lang.
func (p *Printer) FuncMap() template.FuncMap {
	return template.FuncMap{
		"t":           p.T,
		"fmtTime":     p.Time,
		"fmtDuration": p.Duration,
		"lang":        p.Lang,
	}
}

// FuncStubs returns placeholder template functions with the same names as
// FuncMap, for parsing templates before a language is known.
func FuncStubs() template.FuncMap {
	return Default().Printer("en").FuncMap()
}
