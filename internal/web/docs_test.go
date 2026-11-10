package web

import (
	"net/http"
	"strings"
	"testing"
)

// The SQL editor's schema list shows the configured table and column
// descriptions, escaped like any other text.
func TestConsoleShowsDocs(t *testing.T) {
	e := newEnv(t, func(y string) string {
		return strings.Replace(y, "    primary: { host: localhost, read_user: r, write_user: w, sslmode: disable }\n",
			"    primary: { host: localhost, read_user: r, write_user: w, sslmode: disable }\n"+
				"    docs:\n"+
				"      tables:\n"+
				"        public.users:\n"+
				"          description: One row per <b>account</b>.\n"+
				"          columns: { plan: free or pro }\n", 1)
	})
	c, _ := e.login("taro@example.com")
	resp, page := do(t, c, "GET", e.url("/console?db=prod"), nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("console: %d", resp.StatusCode)
	}
	mustContain(t, page, `<li class="schema-desc" dir="auto">One row per &lt;b&gt;account&lt;/b&gt;.</li>`,
		`data-insert="plan" title="free or pro&#10;Insert into the editor"`)
}
