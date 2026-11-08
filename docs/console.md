# SQL editor (web)

The SQL editor (`/console`) is where people run SQL. dbgateway does not offer a path for connecting psql, DBeaver or other desktop clients directly, because such clients could save or export results outside dbgateway's control. People run SQL in the SQL editor and the CLI ([cli.md](cli.md)).

Queries from the editor go through the same gateway as AI agents (parsing, policies, masking, audit log). The editor's features are conveniences; they neither add nor remove safeguards.

## Features

| Feature | Description |
| --- | --- |
| Editor | Syntax highlighting, line numbers, bracket matching. `⌘/Ctrl + Enter` runs the query, `⌘/Ctrl + Shift + Enter` checks the decision. You can run just the selected text |
| Completion | SQL keywords, plus the tables and columns the person is allowed to see. Columns show their type and data class (`masked`, `no_ai`) |
| Tabs | Write drafts in several tabs. Drafts are stored only in the browser (localStorage) and never sent to the server |
| Schema | Opening a table shows its columns, types and data classes. Click to insert into the editor. Listing tables is not audited (searching with the search box is) |
| Check decision | Without running the query, shows allow / approve / deny, the matching rule, the risk, the estimated rows and the columns that will be masked |
| Results | Masked columns are marked. Sort by clicking a column header. A write becomes a pending approval request, with a link to the approval page |
| History | The SQL you ran (as typed), the database, the reason and the outcome. Visible only to you; kept 30 days by default, up to 500 entries |
| Saved queries | Save SQL and the target database under a name (only you, up to 200). Results are not saved |
| Export | CSV (UTF-8 with BOM) and JSON. See below |

Without JavaScript, the page still works as a plain form for running, checking the decision, saving and exporting (completion, tabs and sorting are unavailable).

## Export

- "Export" at the top right of the results re-runs the SQL of the displayed result through the gateway and writes the output
- Read-only: write statements are denied. Not available to AI agents (MCP)
- Masking is the same as for a normal run; masked values stay masked in the export
- The row limit is `console.export_max_rows` (default 10,000 rows). A smaller `max_rows` from the policy takes precedence
- The audit log records `event: export` with the format (`extra.format`) and the row count. Denials are recorded too
- In CSV, values that a spreadsheet would interpret as a formula (starting with `=`, `+`, `-` or `@`) are prefixed with `'`

## Configuration

```yaml
console:
  history: true              # keep executed SQL in the history (default true)
  history_retention: 720h    # how long history is kept (default 30 days)
  export: true               # allow export (default true)
  export_max_rows: 10000     # rows per export (default 10,000)
```

The history stores the SQL as typed (including literals) in the management database. The audit log records normalized SQL with literals removed (when `audit.log_raw_sql: false`), but the history is separate from the audit log. If you do not want literals kept in the management database, set `history: false`.

## Development

The editor component is [CodeMirror 6](https://codemirror.net) (MIT). The source in `web/editor` is bundled by esbuild into a single file, `internal/web/ui/static/editor.js`, which is committed to the repository (building dbgateway does not need Node.js).

```sh
cd web/editor
npm ci
npm run build   # updates internal/web/ui/static/editor.js
```

CI runs the same build and checks that the result matches the committed file. Licenses of the bundled libraries are in [web/editor/THIRD_PARTY_LICENSES](../web/editor/THIRD_PARTY_LICENSES).

CodeMirror injects styles through `<style>` elements, so this page alone adds `style-src 'self' 'nonce-…'` (a per-request nonce) to its CSP. Scripts are still limited to `'self'`.
