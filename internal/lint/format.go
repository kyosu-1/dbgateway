package lint

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Formats of the report.
const (
	FormatText   = "text"
	FormatJSON   = "json"
	FormatGitHub = "github"
)

// Summary counts findings by severity.
type Summary struct {
	Files    int `json:"files"`
	Errors   int `json:"errors"`
	Warnings int `json:"warnings"`
	Infos    int `json:"infos"`
}

// Summarize counts the findings.
func Summarize(files int, findings []Finding) Summary {
	s := Summary{Files: files}
	for _, f := range findings {
		switch f.Severity {
		case SeverityError:
			s.Errors++
		case SeverityWarning:
			s.Warnings++
		default:
			s.Infos++
		}
	}
	return s
}

func (s Summary) String() string {
	return fmt.Sprintf("%d %s, %d %s, %d info in %d %s",
		s.Errors, plural(s.Errors, "error", "errors"),
		s.Warnings, plural(s.Warnings, "warning", "warnings"),
		s.Infos, s.Files, plural(s.Files, "file", "files"))
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// Write writes the findings in a format: text (one finding per line with
// its hint), json (one object) or github (GitHub Actions workflow
// commands, which annotate the pull request).
func Write(w io.Writer, format string, files int, findings []Finding) error {
	switch format {
	case FormatText:
		for _, f := range findings {
			if _, err := fmt.Fprintf(w, "%s:%d:%d: %s %s: %s\n", f.File, f.Line, f.Column, f.Severity, f.Rule, f.Message); err != nil {
				return err
			}
			if f.Hint != "" {
				if _, err := fmt.Fprintf(w, "    hint: %s\n", f.Hint); err != nil {
					return err
				}
			}
		}
		return nil
	case FormatJSON:
		if findings == nil {
			findings = []Finding{}
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(struct {
			Findings []Finding `json:"findings"`
			Summary  Summary   `json:"summary"`
		}{findings, Summarize(files, findings)})
	case FormatGitHub:
		for _, f := range findings {
			cmd := "notice"
			switch f.Severity {
			case SeverityError:
				cmd = "error"
			case SeverityWarning:
				cmd = "warning"
			}
			msg := f.Message
			if f.Hint != "" {
				msg += "\nHint: " + f.Hint
			}
			if _, err := fmt.Fprintf(w, "::%s file=%s,line=%d,col=%d,title=%s::%s\n", cmd,
				ghProperty(f.File), f.Line, f.Column, ghProperty(f.Rule), ghData(msg)); err != nil {
				return err
			}
		}
		return nil
	}
	return fmt.Errorf("unknown format %q (use text, json or github)", format)
}

// ghData escapes a workflow command message.
func ghData(s string) string {
	return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A").Replace(s)
}

// ghProperty escapes a workflow command property value.
func ghProperty(s string) string {
	return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A", ":", "%3A", ",", "%2C").Replace(s)
}
