package rules

import (
	"regexp"
	"strings"
)

// ShellRule detects shell-execution surface in a bundle: raw scripts under a
// scripts/ dir, and inline `curl … | sh` style pipe-to-shell installers (the
// classic supply-chain trojan shape) wherever they appear.
type ShellRule struct{}

// ID implements Rule.
func (ShellRule) ID() string { return "SK-SHELL" }

var (
	// pipeToShell matches `curl …| sh`, `wget …| bash`, `… | sudo bash`, etc.
	// across a single line. This is the highest-signal install-time pattern.
	pipeToShell = regexp.MustCompile(`(?i)(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(sh|bash|zsh)\b`)

	// evalDownload matches `eval "$(curl …)"` / `bash <(curl …)` process
	// substitution that runs remote code without an explicit pipe.
	evalDownload = regexp.MustCompile(`(?i)(eval\s*"?\$\(\s*(curl|wget)|(sh|bash|zsh)\s*<\(\s*(curl|wget))`)

	// scriptShebang matches an interpreter shebang on the first line.
	scriptShebang = regexp.MustCompile(`^#!\s*\S*(sh|bash|zsh|python[0-9.]*|node|ruby|perl)\b`)
)

// Check implements Rule.
func (r ShellRule) Check(files []SourceFile) []Finding {
	var out []Finding
	for _, f := range files {
		lines := strings.Split(f.Content, "\n")

		// A raw executable script under scripts/ is itself shell surface: a
		// skill that ships .sh/.py runs arbitrary code on the host.
		if f.Kind == KindScript {
			snippet := firstNonBlank(lines)
			out = append(out, Finding{
				RuleID:   "SK-SHELL-001",
				Severity: SeverityMedium,
				Surface:  SurfaceShell,
				Reason:   "ships an executable script that runs on the host when the skill is invoked",
				Evidence: Evidence{File: f.Path, Line: shebangLine(lines), Snippet: snippet},
			})
		}

		// Inline pipe-to-shell / eval-download anywhere is high severity.
		for i, line := range lines {
			if pipeToShell.MatchString(line) || evalDownload.MatchString(line) {
				out = append(out, Finding{
					RuleID:   "SK-SHELL-002",
					Severity: SeverityHigh,
					Surface:  SurfaceShell,
					Reason:   "pipes downloaded content straight into a shell (curl|sh style remote-code execution)",
					Evidence: Evidence{File: f.Path, Line: i + 1, Snippet: strings.TrimSpace(line)},
				})
			}
		}
	}
	return out
}

// shebangLine returns the 1-based line number of a shebang, or 1.
func shebangLine(lines []string) int {
	for i, l := range lines {
		if scriptShebang.MatchString(strings.TrimSpace(l)) {
			return i + 1
		}
	}
	return 1
}

func firstNonBlank(lines []string) string {
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if t != "" {
			return t
		}
	}
	return ""
}
