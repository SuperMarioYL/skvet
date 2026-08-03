// Package report renders scan results, either as a human-facing colored table
// (text.go) or as machine-readable JSON (json.go).
package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/fatih/color"

	"github.com/SuperMarioYL/skvet/internal/rules"
	"github.com/SuperMarioYL/skvet/internal/score"
)

// Result is the full output of one scan: the per-bundle verdicts plus the
// overall level and the source that was scanned.
type Result struct {
	Source   string          `json:"source"`
	Bundles  int             `json:"bundles"`
	Overall  score.Level     `json:"overall"`
	Verdicts []score.Verdict `json:"verdicts"`
}

// Text writes a colored findings table + aggregate verdict to w. Colors are
// disabled automatically by fatih/color when w is not a TTY (or NO_COLOR set).
func Text(w io.Writer, r Result) {
	fmt.Fprintf(w, "skvet scan: %s\n", r.Source)
	fmt.Fprintf(w, "discovered %d skill bundle(s)\n\n", r.Bundles)

	for _, v := range r.Verdicts {
		writeBundle(w, v)
	}

	fmt.Fprintln(w, strings.Repeat("─", 64))
	if r.Overall == score.LevelNone {
		// 0 bundles discovered: do NOT print a false-clean "OVERALL RISK: LOW".
		// Say so honestly instead (the aggregate counterpart to the m4 fix).
		fmt.Fprintln(w, color.New(color.Faint).Sprint("OVERALL RISK: n/a — no skill bundle discovered, nothing to assess."))
	} else {
		fmt.Fprintf(w, "OVERALL RISK: %s\n", colorLevel(r.Overall).Sprint(string(r.Overall)))
	}
	// The load-bearing, stars-orthogonal reminder.
	fmt.Fprintln(w, color.New(color.Faint).Sprint("note: stars ≠ safe — a 41k-star repo can still curl|sh on install."))
}

func writeBundle(w io.Writer, v score.Verdict) {
	bold := color.New(color.Bold)
	label := v.BundlePath
	if v.BundleName != "" {
		label = fmt.Sprintf("%s (%s)", v.BundlePath, v.BundleName)
	}
	fmt.Fprintf(w, "%s  [%s]  score %d/100\n",
		bold.Sprint(label),
		colorLevel(v.Level).Sprint(string(v.Level)),
		v.Score,
	)

	if len(v.Findings) == 0 {
		fmt.Fprintln(w, "  "+color.New(color.FgGreen).Sprint("✓ no shell / hook / network surface detected (pure prompt)"))
		fmt.Fprintln(w)
		return
	}

	// Header.
	fmt.Fprintf(w, "  %-12s %-8s %-11s %s\n", "RULE", "SEV", "SURFACE", "EVIDENCE")
	for _, f := range v.Findings {
		fmt.Fprintf(w, "  %-12s %-8s %-11s %s\n",
			f.RuleID,
			colorSeverity(f.Severity).Sprint(string(f.Severity)),
			string(f.Surface),
			evidenceLine(f),
		)
		fmt.Fprintf(w, "  %-12s %-8s %-11s %s\n", "", "", "", color.New(color.Faint).Sprint("→ "+f.Reason))
	}
	fmt.Fprintln(w)
}

func evidenceLine(f rules.Finding) string {
	loc := f.Evidence.File
	if f.Evidence.Line > 0 {
		loc = fmt.Sprintf("%s:%d", f.Evidence.File, f.Evidence.Line)
	}
	snip := f.Evidence.Snippet
	if len(snip) > 60 {
		snip = snip[:57] + "..."
	}
	if snip == "" {
		return loc
	}
	return fmt.Sprintf("%s  %s", loc, snip)
}

func colorLevel(l score.Level) *color.Color {
	switch l {
	case score.LevelHigh:
		return color.New(color.FgRed, color.Bold)
	case score.LevelMedium:
		return color.New(color.FgYellow, color.Bold)
	default:
		return color.New(color.FgGreen, color.Bold)
	}
}

func colorSeverity(s rules.Severity) *color.Color {
	switch s {
	case rules.SeverityHigh:
		return color.New(color.FgRed)
	case rules.SeverityMedium:
		return color.New(color.FgYellow)
	default:
		return color.New(color.FgWhite)
	}
}
