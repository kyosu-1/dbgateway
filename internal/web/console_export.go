package web

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kyosu-1/dbgateway/internal/gateway"
)

// consoleExport runs the statement again as an export and sends the
// result as a CSV or JSON download. The gateway accepts only reads,
// applies the same masking and audits it as event "export"; denials and
// errors are shown in the editor instead.
func (a *App) consoleExport(w http.ResponseWriter, r *http.Request, v *viewer, dbs []gateway.DatabaseInfo, f consoleForm, res *consoleResult) {
	format := r.PostFormValue("format")
	switch {
	case !a.cfg.Console.ExportEnabled():
		res.Error = "console.error_export_disabled"
	case format != "csv" && format != "json":
		res.Error = "console.error_export_format"
	case f.Reason == "":
		res.Error = "console.error_reason"
	}
	if res.Error != "" {
		a.renderConsole(w, r, v, http.StatusBadRequest, dbs, f, res, consoleOpen{})
		return
	}
	sqlText := f.executed()
	resp := a.gw.ExecuteSQL(r.Context(), consolePrincipal(v.p), gateway.ExecuteRequest{Database: f.DB, SQL: sqlText,
		Reason: f.Reason, Export: format, ExportMaxRows: a.cfg.Console.ExportRows()})
	if resp.Status != gateway.StatusOK {
		resp.Reason, resp.Hint = inertExport(resp.Reason), inertExport(resp.Hint)
		res.Exec, res.SQL = resp, sqlText
		a.renderConsole(w, r, v, http.StatusOK, dbs, f, res, consoleOpen{})
		return
	}
	name := fmt.Sprintf("dbgw-%s-%s.%s", fileSafe.ReplaceAllString(f.DB, "_"), a.now().UTC().Format("20060102-150405"), format)
	h := w.Header()
	h.Set("Content-Disposition", `attachment; filename="`+name+`"`)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Dbgw-Request-Id", resp.RequestID)
	if resp.Truncated {
		h.Set("X-Dbgw-Truncated", "true")
	}
	if format == "json" {
		h.Set("Content-Type", "application/json; charset=utf-8")
		writeExportJSON(w, resp)
		return
	}
	h.Set("Content-Type", "text/csv; charset=utf-8")
	writeExportCSV(w, resp)
}

var fileSafe = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func inertExport(s string) string { return strings.ToValidUTF8(s, "") }

// writeExportCSV writes a header row and the rows. Cells that a
// spreadsheet would read as a formula are prefixed with ' (CSV injection).
func writeExportCSV(w http.ResponseWriter, resp *gateway.ExecuteResponse) {
	_, _ = w.Write([]byte("\xef\xbb\xbf")) // UTF-8 BOM so that spreadsheets detect the encoding
	cw := csv.NewWriter(w)
	cw.UseCRLF = true // RFC 4180
	header := make([]string, len(resp.Columns))
	for i, c := range resp.Columns {
		header[i] = csvSafe(c.Name)
	}
	_ = cw.Write(header)
	record := make([]string, len(resp.Columns))
	for _, row := range resp.Rows {
		for i := range record {
			record[i] = ""
			if i < len(row) && row[i] != nil {
				record[i] = csvSafe(exportText(row[i]))
			}
		}
		_ = cw.Write(record)
	}
	cw.Flush()
}

func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

// exportText renders a value without the display truncation of the page.
func exportText(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case []byte:
		if utf8.Valid(x) {
			return string(x)
		}
		return fmt.Sprintf("\\x%x", x)
	case time.Time:
		return x.Format(time.RFC3339Nano)
	case fmt.Stringer:
		return x.String()
	case bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64, json.Number:
		return fmt.Sprint(x)
	}
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}

// writeExportJSON writes {columns, rows, truncated, request_id}. Columns
// carry the masking flags; values keep their JSON types.
func writeExportJSON(w http.ResponseWriter, resp *gateway.ExecuteResponse) {
	rows := resp.Rows
	if rows == nil {
		rows = [][]any{}
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(map[string]any{"request_id": resp.RequestID, "columns": resp.Columns, "rows": rows, "truncated": resp.Truncated})
}
