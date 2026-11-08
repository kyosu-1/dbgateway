package auth

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kyosu-1/dbgateway/internal/config"
	"github.com/kyosu-1/dbgateway/internal/identity"
)

type fakeSlack struct {
	mu     sync.Mutex
	linked map[string]string
	fail   bool
}

func (f *fakeSlack) Linked(email string) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.linked[email]
	return u, ok
}

func (f *fakeSlack) IssueCode(string) (string, time.Time, error) {
	if f.fail {
		return "", time.Time{}, errors.New("slack down")
	}
	return "ABCD-1234", time.Now().Add(10 * time.Minute), nil
}

func (f *fakeSlack) Unlink(email string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.linked, email)
	return nil
}

func TestAccountSlackSection(t *testing.T) {
	e := newEnv(t, testConfig, nil)
	b := e.browser()
	e.login(b, "taro@example.com")
	_, page := do(t, b, "GET", e.url("/account"), nil)
	if strings.Contains(page, `id="h-slack"`) {
		t.Fatal("Slack section shown without a linker")
	}
	csrf := csrfFrom(t, page)
	if resp, _ := do(t, b, "POST", e.url("/account/slack/link"), url.Values{"csrf": {csrf}}); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("link without a linker: %d", resp.StatusCode)
	}

	sl := &fakeSlack{linked: map[string]string{}}
	e.auth.SetSlackLinker(sl)
	_, page = do(t, b, "GET", e.url("/account"), nil)
	if !strings.Contains(page, `action="/account/slack/link"`) {
		t.Fatalf("no link button:\n%s", page)
	}
	if resp, _ := do(t, b, "POST", e.url("/account/slack/link"), url.Values{"csrf": {"bad"}}); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("link without csrf: %d", resp.StatusCode)
	}
	resp, page := do(t, b, "POST", e.url("/account/slack/link"), url.Values{"csrf": {csrf}})
	if resp.StatusCode != http.StatusOK || !strings.Contains(page, "/dbgw link ABCD-1234") {
		t.Fatalf("link: %d\n%s", resp.StatusCode, page)
	}
	sl.linked["taro@example.com"] = "@taro"
	_, page = do(t, b, "GET", e.url("/account"), nil)
	if !strings.Contains(page, "Linked to @taro") {
		t.Fatalf("linked state:\n%s", page)
	}
	resp, _ = do(t, b, "POST", e.url("/account/slack/unlink"), url.Values{"csrf": {csrf}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/account?slack=unlinked" {
		t.Fatalf("unlink: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if _, ok := sl.Linked("taro@example.com"); ok {
		t.Fatal("still linked")
	}
}

func TestAccountPersonalRoleBindingsAndLanguage(t *testing.T) {
	until := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second)
	e := newEnv(t, testConfig, func(c *config.Config) {
		c.RoleBindings = append(c.RoleBindings, config.RoleBinding{User: "taro@example.com", Databases: config.DatabaseSelector{Names: []string{"analytics"}},
			Roles: []identity.Role{identity.RoleQuerier}, ExpiresAt: &until})
	})
	b := e.browser()
	e.login(b, "taro@example.com")
	_, page := do(t, b, "GET", e.url("/account"), nil)
	if !strings.Contains(page, "<dt>analytics</dt>") || !strings.Contains(page, `class="note-warn"`) {
		t.Fatalf("personal binding not shown:\n%s", page)
	}
	// Language: choose Japanese, then follow the browser again.
	resp, _ := do(t, b, "GET", e.url("/account?lang=ja"), nil)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("switch: %d", resp.StatusCode)
	}
	_, page = do(t, b, "GET", e.url("/account"), nil)
	if !strings.Contains(page, `<html lang="ja">`) || !strings.Contains(page, `<option value="ja" lang="ja" selected>`) {
		t.Fatalf("Japanese not selected:\n%s", page[:400])
	}
	do(t, b, "GET", e.url("/account?lang=auto"), nil)
	_, page = do(t, b, "GET", e.url("/account"), nil)
	if !strings.Contains(page, `<html lang="en">`) || !strings.Contains(page, `<option value="auto" selected>`) {
		t.Fatalf("auto not selected:\n%s", page[:400])
	}
}
