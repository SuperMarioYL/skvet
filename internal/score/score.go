// Package score aggregates a bundle's findings into a single 0-100 risk score
// and a LOW/MEDIUM/HIGH level. The whole point of skvet is that this score is
// orthogonal to social proof: star count never enters the calculation, and the
// report carries an explicit "stars != safe" reminder.
package score

import (
	"strings"

	"github.com/SuperMarioYL/skvet/internal/rules"
)

// Level is the coarse risk verdict shown to the user.
type Level string

const (
	// LevelNone is a sentinel used only by --fail-on none: it is never emitted
	// as a verdict's level, and as a fail-threshold it means "never exit 2".
	LevelNone Level = "NONE"
	LevelLow    Level = "LOW"
	LevelMedium Level = "MEDIUM"
	LevelHigh   Level = "HIGH"
)

// ParseLevel maps the --fail-on flag's string value to a Level. "none"
// resolves to the LevelNone sentinel; ok is false for anything else.
func ParseLevel(s string) (Level, bool) {
	switch strings.ToLower(s) {
	case "":
		return "", false
	case "none":
		return LevelNone, true
	case "low":
		return LevelLow, true
	case "medium":
		return LevelMedium, true
	case "high":
		return LevelHigh, true
	default:
		return "", false
	}
}

// AtLeast reports whether this level is at or above min in severity. It is
// used by the --fail-on gate: an overall level meets the threshold when its
// rank is >= the threshold's rank. LevelNone has rank 0 so any real level is
// "at least" none — callers gate --fail-on none separately.
func (l Level) AtLeast(min Level) bool {
	return levelRank(l) >= levelRank(min)
}

// Verdict is the aggregated risk for one bundle.
type Verdict struct {
	BundlePath  string          `json:"bundle"`
	BundleName  string          `json:"name,omitempty"`
	Score       int             `json:"score"` // 0-100, higher = riskier
	Level       Level           `json:"level"`
	Findings    []rules.Finding `json:"findings"`
	StarsNote   string          `json:"stars_note"`
	TopFindings []rules.Finding `json:"top_findings"`
}

// per-severity point weights. Tuned so a single high finding lands in MEDIUM
// and any two high (or one high + supporting surface) lands in HIGH.
const (
	weightHigh   = 40
	weightMedium = 15
	weightLow    = 5

	thresholdMedium = 15 // >= this is at least MEDIUM
	thresholdHigh   = 50 // >= this is HIGH
)

// starsNote is the fixed, stars-orthogonal reminder. It is intentionally not
// parameterized on a real star count: the score never reads stars, so the line
// states the principle rather than a fetched number.
const starsNote = "Risk is computed from capability surface only — stars are gameable and do NOT make a bundle safe."

// Aggregate turns a bundle's findings into a Verdict.
func Aggregate(bundlePath string, findings []rules.Finding) Verdict {
	total := 0
	for _, f := range findings {
		switch f.Severity {
		case rules.SeverityHigh:
			total += weightHigh
		case rules.SeverityMedium:
			total += weightMedium
		case rules.SeverityLow:
			total += weightLow
		}
	}
	if total > 100 {
		total = 100
	}

	level := LevelLow
	switch {
	case total >= thresholdHigh:
		level = LevelHigh
	case total >= thresholdMedium:
		level = LevelMedium
	}

	// A single high-severity finding (an auto-running hook, or a curl|sh
	// remote-code-execution line) is independently disqualifying: it runs
	// arbitrary code on the host, so the bundle is HIGH regardless of how the
	// points happen to add up.
	for _, f := range findings {
		if f.Severity == rules.SeverityHigh {
			level = LevelHigh
			break
		}
	}

	sorted := make([]rules.Finding, len(findings))
	copy(sorted, findings)
	rules.SortFindings(sorted)

	top := sorted
	if len(top) > 3 {
		top = top[:3]
	}

	return Verdict{
		BundlePath:  bundlePath,
		Score:       total,
		Level:       level,
		Findings:    sorted,
		StarsNote:   starsNote,
		TopFindings: top,
	}
}

// Overall reduces several bundle verdicts to the single worst level, for the
// repo-wide summary line. An empty verdict slice (0 bundles discovered) yields
// LevelNone so the report prints an honest "nothing to assess" line instead of a
// false-clean "OVERALL RISK: LOW" — the aggregate version of the m4 fix.
func Overall(verdicts []Verdict) Level {
	worst := LevelNone
	for _, v := range verdicts {
		if levelRank(v.Level) > levelRank(worst) {
			worst = v.Level
		}
	}
	return worst
}

func levelRank(l Level) int {
	switch l {
	case LevelHigh:
		return 3
	case LevelMedium:
		return 2
	case LevelLow:
		return 1
	default:
		return 0
	}
}
