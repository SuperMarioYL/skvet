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
	httpClient = regexp.MustCompile(`(?i)(requests\.(get|post)|urllib\.request|http\.client|fetch\(|axios\.|net/http|httpx\.)`)
	localHost  = regexp.MustCompile(`(?i)https?://(localhost|127\.0\.0\.1|0\.0\.0\.0)`)
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
			urls := httpURL.FindAllString(line, -1)
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
			hasCmd := netCmd.MatchString(line) && (hasRemoteURL || !hasAnyURL)
			// But a bare network command with no URL at all on the line is still
			// only interesting if nothing local contradicts it.
			if netCmd.MatchString(line) && hasAnyURL && !hasRemoteURL {
				hasCmd = false
			}
			hasURL := hasRemoteURL
			hasClient := httpClient.MatchString(line)
			if !hasCmd && !hasURL && !hasClient {
				continue
			}
			sev := SeverityMedium
			reason := "makes an outbound network call from an executable file"
			if hasCmd && hasURL {
				// A network command pointed at a concrete remote host is the
				// strongest exfil/fetch signal short of a pipe-to-shell.
				sev = SeverityMedium
				reason = "fetches from a remote host using a network command (curl/wget/etc.)"
			}
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
