// Package score aggregates a bundle's findings into a single 0-100 risk score
// and a LOW/MEDIUM/HIGH level. The whole point of skvet is that this score is
// orthogonal to social proof: star count never enters the calculation, and the
// report carries an explicit "stars != safe" reminder.
package score

import (
	"github.com/SuperMarioYL/skvet/internal/rules"
)

// Level is the coarse risk verdict shown to the user.
type Level string

const (
	LevelLow    Level = "LOW"
	LevelMedium Level = "MEDIUM"
	LevelHigh   Level = "HIGH"
)

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
// repo-wide summary line.
func Overall(verdicts []Verdict) Level {
	worst := LevelLow
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
