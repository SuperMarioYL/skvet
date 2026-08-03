package score

import (
	"testing"

	"github.com/SuperMarioYL/skvet/internal/rules"
)

func TestAggregate_PurePromptIsLow(t *testing.T) {
	v := Aggregate("benign", nil)
	if v.Level != LevelLow {
		t.Fatalf("expected LOW for no findings, got %s", v.Level)
	}
	if v.Score != 0 {
		t.Fatalf("expected score 0, got %d", v.Score)
	}
	if v.StarsNote == "" {
		t.Fatal("stars note must always be present (stars-orthogonal invariant)")
	}
}

func TestAggregate_SingleHighIsAtLeastMedium(t *testing.T) {
	f := []rules.Finding{{RuleID: "SK-HOOK-001", Severity: rules.SeverityHigh, Surface: rules.SurfaceHook}}
	v := Aggregate("b", f)
	if levelRank(v.Level) < levelRank(LevelMedium) {
		t.Fatalf("a single high finding must be >= MEDIUM, got %s", v.Level)
	}
}

func TestAggregate_HookPlusNetIsHigh(t *testing.T) {
	f := []rules.Finding{
		{RuleID: "SK-HOOK-001", Severity: rules.SeverityHigh, Surface: rules.SurfaceHook},
		{RuleID: "SK-SHELL-002", Severity: rules.SeverityHigh, Surface: rules.SurfaceShell},
	}
	v := Aggregate("b", f)
	if v.Level != LevelHigh {
		t.Fatalf("two high findings must be HIGH, got %s (score %d)", v.Level, v.Score)
	}
}

func TestAggregate_ScoreCappedAt100(t *testing.T) {
	var f []rules.Finding
	for i := 0; i < 10; i++ {
		f = append(f, rules.Finding{Severity: rules.SeverityHigh})
	}
	v := Aggregate("b", f)
	if v.Score != 100 {
		t.Fatalf("score must cap at 100, got %d", v.Score)
	}
}

func TestAggregate_TopFindingsLimited(t *testing.T) {
	var f []rules.Finding
	for i := 0; i < 5; i++ {
		f = append(f, rules.Finding{RuleID: "X", Severity: rules.SeverityMedium})
	}
	v := Aggregate("b", f)
	if len(v.TopFindings) != 3 {
		t.Fatalf("expected top 3, got %d", len(v.TopFindings))
	}
}

func TestOverall_WorstWins(t *testing.T) {
	got := Overall([]Verdict{{Level: LevelLow}, {Level: LevelHigh}, {Level: LevelMedium}})
	if got != LevelHigh {
		t.Fatalf("expected HIGH overall, got %s", got)
	}
}

// TestOverall_EmptyIsNone: a 0-bundle scan must NOT default to a false-clean
// LOW aggregate (the m4 fix's aggregate counterpart, m7).
func TestOverall_EmptyIsNone(t *testing.T) {
	got := Overall(nil)
	if got != LevelNone {
		t.Fatalf("0 bundles must yield LevelNone (not LOW), got %s", got)
	}
	if got.AtLeast(LevelLow) {
		t.Fatalf("LevelNone must not meet the LOW threshold (got %s)", got)
	}
}
