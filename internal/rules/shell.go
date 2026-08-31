package rules

import (
	"regexp"
	"strconv"
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
	// The post-pipe shell target accepts bare names (sh|bash|zsh) AND absolute
	// paths (`/bin/sh`, `/usr/bin/bash`, `/bin/zsh`) so an RCE installer that
	// pipes into an absolute-path shell cannot slip past SK-SHELL-002 HIGH;
	// an optional `sudo [-E]` / `exec` prefix is also accepted
	// (`| sudo -E bash`, `| exec sh`). The wrapper alternation ALSO accepts
	// `env` (bare `| env bash` and pathed `| /usr/bin/env bash`) — the
	// canonical *portable* interpreter invocation (same shape as the most
	// common shebang `#!/usr/bin/env bash`), so a portable RCE installer
	// cannot evade the headline detector. Bare `sh`/`bash`/`zsh` still match.
	pipeToShell = regexp.MustCompile(`(?i)(curl|wget)\b[^\n|]*\|\s*(?:(?:sudo(?:\s+-E)?|exec|env|/(?:usr/)?bin/env)\s+)?(?:/(?:usr/)?bin/)?(?:sh|bash|zsh)\b`)

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
		//
		// evalDownload (`eval "$(curl …)"` / `bash <(curl …)`) is matched
		// against the WHOLE file content, not per logical line: it can span
		// bare newlines inside a `$(...)` command substitution, where `eval
		// "$(` lands on one line and `curl` on the next. `eval "$(` ends with
		// `(` — not a backslash or pipe — so logicalLines (below) does NOT join
		// the two, and a per-line match would miss the RCE. evalDownload's `\s*`
		// spans newlines, so the single- and multi-line forms both trip
		// SK-SHELL-002 HIGH — the remote-code-execution shape skvet exists to
		// block.
		//
		// pipeToShell keeps a per-logical-line match: its `[^\n|]` class
		// excludes newlines, so a wrapped `curl … | \<newline> sh` or
		// `curl … |<newline>sh` is joined by logicalLines into one line and
		// matched there (the single-line regex would otherwise miss the wrapped
		// shape and the bundle would score MEDIUM instead of a disqualifying
		// HIGH).
		//
		// But only on executable surfaces: a `curl … | sh` (or
		// `eval "$(curl …)"`) documented in a pure-prompt SKILL.md / README
		// (KindMarkdown / KindManifest) is prose quoting an install command, an
		// anti-pattern example, or skvet's own warning — not a runtime
		// shell-exec surface. Skipping these kinds preserves the "pure prompt =
		// LOW" guarantee and mirrors NetworkRule's executable-surfaces-only guard
		// (network.go). Scripts (KindScript), hooks.json (KindHooksJSON), and
		// data/config files (KindOther) stay covered.
		if f.Kind == KindMarkdown || f.Kind == KindManifest {
			continue
		}
		for _, loc := range evalDownload.FindAllStringIndex(f.Content, -1) {
			out = append(out, Finding{
				RuleID:   "SK-SHELL-002",
				Severity: SeverityHigh,
				Surface:  SurfaceShell,
				Reason:   "pipes downloaded content straight into a shell (curl|sh style remote-code execution)",
				Evidence: Evidence{File: f.Path, Line: lineOf(f.Content, loc[0]), Snippet: matchedLinesSnippet(f.Content, loc[0], loc[1])},
			})
		}
		for _, ll := range logicalLines(lines) {
			if pipeToShell.MatchString(ll.text) {
				out = append(out, Finding{
					RuleID:   "SK-SHELL-002",
					Severity: SeverityHigh,
					Surface:  SurfaceShell,
					Reason:   "pipes downloaded content straight into a shell (curl|sh style remote-code execution)",
					Evidence: Evidence{File: f.Path, Line: ll.line, Snippet: strings.TrimSpace(ll.text)},
				})
			}
		}
	}
	// A single line that trips both evalDownload (full-content match) and
	// pipeToShell (logical-line match) — e.g. `eval "$(curl … | sh)"` — must
	// yield one SK-SHELL-002 finding, not two. The reason string is identical,
	// so deduping by (file, line) and keeping either is equivalent.
	return dedupShell002(out)
}

// logicalLine is one logical (continuation-joined) line and the 1-based number
// of the physical line it starts on.
type logicalLine struct {
	text string
	line int
}

// logicalLines joins shell line-continuations so a pipe-to-shell split across a
// trailing backslash or a trailing pipe is matched as one logical line. Lines
// with no continuation are returned 1:1 with the input.
func logicalLines(lines []string) []logicalLine {
	var out []logicalLine
	for i := 0; i < len(lines); i++ {
		start := i + 1
		cur := lines[i]
		for endsWithContinuation(cur) && i+1 < len(lines) {
			i++
			cur = joinContinuation(cur, lines[i])
		}
		out = append(out, logicalLine{text: cur, line: start})
	}
	return out
}

// endsWithContinuation reports whether a line signals that the next line is a
// continuation: a trailing backslash (shell line continuation) or a trailing
// bare pipe (the pipe target starts on the next line).
func endsWithContinuation(line string) bool {
	t := strings.TrimRight(line, " \t\r")
	if len(t) == 0 {
		return false
	}
	switch t[len(t)-1] {
	case '\\', '|':
		return true
	}
	return false
}

// joinContinuation merges a continuation head with its successor: strip a
// trailing line-continuation backslash (if any), then join with a single space
// so the regex sees `curl ... | sh` as one line.
func joinContinuation(head, next string) string {
	t := strings.TrimRight(head, " \t\r")
	if strings.HasSuffix(t, "\\") {
		t = strings.TrimSuffix(t, "\\")
	}
	return t + " " + strings.TrimLeft(next, " \t\r")
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

// lineOf returns the 1-based line number of the byte offset in content.
func lineOf(content string, offset int) int {
	if offset < 0 {
		return 1
	}
	if offset > len(content) {
		offset = len(content)
	}
	return strings.Count(content[:offset], "\n") + 1
}

// matchedLinesSnippet returns the text from the start of the line containing
// matchStart through the end of the line containing matchEnd, with embedded
// newlines collapsed to single spaces. A multi-line `eval "$(\n  curl…"`
// is thus rendered as one readable evidence snippet instead of just the
// truncated `eval "$(` line.
func matchedLinesSnippet(content string, matchStart, matchEnd int) string {
	start := matchStart
	if start < 0 {
		start = 0
	}
	for start > 0 && content[start-1] != '\n' {
		start--
	}
	end := matchEnd
	if end > len(content) {
		end = len(content)
	}
	if end < start {
		end = start
	}
	for end < len(content) && content[end] != '\n' {
		end++
	}
	return strings.TrimSpace(strings.ReplaceAll(content[start:end], "\n", " "))
}

// dedupShell002 drops duplicate SK-SHELL-002 findings that share the same
// (file, line) — e.g. a line that trips both the evalDownload full-content
// match and the pipeToShell logical-line match. Other findings pass through.
func dedupShell002(findings []Finding) []Finding {
	seen := make(map[string]bool)
	out := make([]Finding, 0, len(findings))
	for _, f := range findings {
		if f.RuleID == "SK-SHELL-002" {
			key := f.Evidence.File + "\x00" + strconv.Itoa(f.Evidence.Line)
			if seen[key] {
				continue
			}
			seen[key] = true
		}
		out = append(out, f)
	}
	return out
}
