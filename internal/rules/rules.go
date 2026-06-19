// Package rules defines the deterministic capability-surface detectors that
// skvet runs over an installable agent-skill bundle, plus the shared types
// (Finding, Severity, Surface) that the detectors emit.
//
// A rule is a pure function over a bundle's already-read files: it never does
// I/O of its own, so the engine is fully testable on in-memory fixtures.
package rules

import "sort"

// Severity ranks how dangerous a finding is. Order matters for sorting and
// for the score aggregator, so keep High > Medium > Low.
type Severity string

const (
	// SeverityHigh marks capabilities that can run arbitrary code or exfiltrate
	// data the instant a bundle is installed or invoked.
	SeverityHigh Severity = "high"
	// SeverityMedium marks capabilities worth a human glance before trusting.
	SeverityMedium Severity = "medium"
	// SeverityLow marks informational surface that is rarely dangerous alone.
	SeverityLow Severity = "low"
)

// rank gives a numeric weight to a severity for sorting / scoring.
func (s Severity) rank() int {
	switch s {
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// Surface names the capability category a finding belongs to. These mirror the
// core primitive in the product spec (shell, hook, fs_write, network, secrets,
// obfuscation).
type Surface string

const (
	SurfaceShell       Surface = "shell"
	SurfaceHook        Surface = "hook"
	SurfaceNetwork     Surface = "network"
	SurfaceObfuscation Surface = "obfuscation"
	SurfaceSecrets     Surface = "secrets"
)

// Evidence pins a finding to a concrete location so the report can show the
// user exactly what tripped the rule.
type Evidence struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Snippet string `json:"snippet"`
}

// Finding is a single capability detected in a bundle.
type Finding struct {
	RuleID   string   `json:"rule_id"`
	Severity Severity `json:"severity"`
	Surface  Surface  `json:"surface"`
	Reason   string   `json:"reason"`
	Evidence Evidence `json:"evidence"`
}

// SourceFile is one already-read file from a bundle. The engine reads files
// once during discovery and hands their contents to every rule, so rules stay
// pure and the file system is only touched in one place.
type SourceFile struct {
	// Path is the bundle-relative path, used in evidence and reports.
	Path string
	// Kind classifies the file so rules can target the right surface
	// (e.g. only hooks.go cares about "hooks_json").
	Kind FileKind
	// Content is the raw bytes as text.
	Content string
}

// FileKind classifies a source file by its role in a skill bundle.
type FileKind string

const (
	// KindScript is a raw shell/python script under a scripts/ dir.
	KindScript FileKind = "script"
	// KindHooksJSON is a plugin-level hooks/hooks.json declaration.
	KindHooksJSON FileKind = "hooks_json"
	// KindManifest is a SKILL.md / skill.yaml / plugin.json manifest.
	KindManifest FileKind = "manifest"
	// KindMarkdown is a prompt/doc markdown file (e.g. SKILL.md body).
	KindMarkdown FileKind = "markdown"
	// KindOther is anything else worth scanning for inline shell/network.
	KindOther FileKind = "other"
)

// Rule is one detector. Implementations inspect the supplied files and return
// any findings. Rules MUST be pure (no I/O, no globals).
type Rule interface {
	// ID is the stable rule identifier, e.g. "SK-SHELL-001".
	ID() string
	// Check runs the detector over the bundle's files.
	Check(files []SourceFile) []Finding
}

// DefaultRules is the rule set every scan runs.
func DefaultRules() []Rule {
	return []Rule{
		ShellRule{},
		HooksRule{},
		NetworkRule{},
	}
}

// Run executes every rule over the files and returns a sorted, deterministic
// list of findings (high severity first, then by rule id + file + line).
func Run(ruleset []Rule, files []SourceFile) []Finding {
	var all []Finding
	for _, r := range ruleset {
		all = append(all, r.Check(files)...)
	}
	SortFindings(all)
	return all
}

// SortFindings orders findings most-severe-first for stable rendering.
func SortFindings(f []Finding) {
	sort.SliceStable(f, func(i, j int) bool {
		ri, rj := f[i].Severity.rank(), f[j].Severity.rank()
		if ri != rj {
			return ri > rj
		}
		if f[i].RuleID != f[j].RuleID {
			return f[i].RuleID < f[j].RuleID
		}
		if f[i].Evidence.File != f[j].Evidence.File {
			return f[i].Evidence.File < f[j].Evidence.File
		}
		return f[i].Evidence.Line < f[j].Evidence.Line
	})
}
