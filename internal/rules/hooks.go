package rules

import (
	"encoding/json"
	"sort"
	"strings"
)

// HooksRule parses a plugin-level hooks/hooks.json and flags every shell
// command wired to a lifecycle event. Hooks are the most dangerous surface in
// a skill bundle: a PreToolUse/Stop command runs automatically, with no user
// action, every time the agent hits that event.
type HooksRule struct{}

// ID implements Rule.
func (HooksRule) ID() string { return "SK-HOOK" }

// hooksFile mirrors the real on-disk shape:
//
//	{ "hooks": { "PreToolUse": [ { "hooks": [ { "type":"command",
//	  "command":"bash ${CLAUDE_PLUGIN_ROOT}/hooks/x.sh" } ] } ] } }
type hooksFile struct {
	Hooks map[string][]hookMatcher `json:"hooks"`
}

type hookMatcher struct {
	Matcher string     `json:"matcher"`
	Hooks   []hookSpec `json:"hooks"`
}

type hookSpec struct {
	Type    string `json:"type"`
	Command string `json:"command"`
}

// Check implements Rule.
func (r HooksRule) Check(files []SourceFile) []Finding {
	var out []Finding
	for _, f := range files {
		if f.Kind != KindHooksJSON {
			continue
		}
		var hf hooksFile
		if err := json.Unmarshal([]byte(f.Content), &hf); err != nil {
			// Malformed hooks.json is itself worth surfacing — a bundle that
			// can't be parsed can't be trusted.
			out = append(out, Finding{
				RuleID:   "SK-HOOK-000",
				Severity: SeverityLow,
				Surface:  SurfaceHook,
				Reason:   "hooks.json present but could not be parsed; manual review recommended",
				Evidence: Evidence{File: f.Path, Line: 1, Snippet: firstNonBlank(strings.Split(f.Content, "\n"))},
			})
			continue
		}

		for _, event := range sortedKeys(hf.Hooks) {
			for _, m := range hf.Hooks[event] {
				for _, h := range m.Hooks {
					if h.Type != "command" || strings.TrimSpace(h.Command) == "" {
						continue
					}
					sev := SeverityHigh
					reason := "registers a " + event + " hook that auto-runs a shell command on the host"
					// Auto-firing lifecycle events (no tool gate) are the worst.
					if isAutoEvent(event) {
						reason = "registers an auto-firing " + event + " hook that runs a shell command with no user action"
					}
					out = append(out, Finding{
						RuleID:   "SK-HOOK-001",
						Severity: sev,
						Surface:  SurfaceHook,
						Reason:   reason,
						Evidence: Evidence{File: f.Path, Line: 1, Snippet: strings.TrimSpace(h.Command)},
					})
				}
			}
		}
	}
	return out
}

// isAutoEvent reports whether the hook fires without an explicit tool match
// (i.e. on every prompt/stop), which carries the broadest blast radius.
func isAutoEvent(event string) bool {
	switch event {
	case "Stop", "SubagentStop", "UserPromptSubmit", "SessionStart", "Notification":
		return true
	default:
		return false
	}
}

func sortedKeys(m map[string][]hookMatcher) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
