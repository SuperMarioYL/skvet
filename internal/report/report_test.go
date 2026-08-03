package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/SuperMarioYL/skvet/internal/rules"
	"github.com/SuperMarioYL/skvet/internal/score"
)

func sampleResult() Result {
	v := score.Aggregate("malicious-skill", []rules.Finding{
		{
			RuleID:   "SK-HOOK-001",
			Severity: rules.SeverityHigh,
			Surface:  rules.SurfaceHook,
			Reason:   "auto-firing Stop hook",
			Evidence: rules.Evidence{File: "hooks/hooks.json", Line: 1, Snippet: "bash phone-home.sh"},
		},
	})
	return Result{
		Source:   "github.com/owner/repo",
		Bundles:  1,
		Overall:  score.Overall([]score.Verdict{v}),
		Verdicts: []score.Verdict{v},
	}
}

func TestJSON_RoundTrips(t *testing.T) {
	var buf bytes.Buffer
	if err := JSON(&buf, sampleResult()); err != nil {
		t.Fatal(err)
	}
	var back Result
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatalf("json must round-trip: %v\n%s", err, buf.String())
	}
	if back.Overall != score.LevelHigh {
		t.Fatalf("expected HIGH in json, got %s", back.Overall)
	}
	if len(back.Verdicts) != 1 || len(back.Verdicts[0].Findings) != 1 {
		t.Fatalf("findings did not survive json: %+v", back.Verdicts)
	}
	if back.Verdicts[0].StarsNote == "" {
		t.Fatal("stars note must be present in json output")
	}
}

func TestText_ContainsVerdictAndStarsNote(t *testing.T) {
	var buf bytes.Buffer
	Text(&buf, sampleResult())
	out := buf.String()

	for _, want := range []string{"HIGH", "malicious-skill", "SK-HOOK-001", "stars"} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q\n---\n%s", want, out)
		}
	}
}

func TestText_BenignShowsGreenLine(t *testing.T) {
	v := score.Aggregate("benign", nil)
	var buf bytes.Buffer
	Text(&buf, Result{Source: "./x", Bundles: 1, Overall: score.LevelLow, Verdicts: []score.Verdict{v}})
	if !strings.Contains(buf.String(), "pure prompt") {
		t.Errorf("benign bundle should show the pure-prompt line:\n%s", buf.String())
	}
}

// TestText_EmptyScanNoFalseLowAggregate: a 0-bundle scan must NOT print a
// false-clean "OVERALL RISK: LOW"; it prints an honest "nothing to assess"
// line instead (the m4 fix's aggregate counterpart, m7).
func TestText_EmptyScanNoFalseLowAggregate(t *testing.T) {
	var buf bytes.Buffer
	Text(&buf, Result{Source: "./empty", Bundles: 0, Overall: score.Overall(nil), Verdicts: nil})
	out := buf.String()
	if strings.Contains(out, "OVERALL RISK: LOW") {
		t.Fatalf("0-bundle scan must not print a false-clean OVERALL RISK: LOW:\n%s", out)
	}
	if !strings.Contains(out, "nothing to assess") {
		t.Fatalf("0-bundle scan should print the honest nothing-to-assess line:\n%s", out)
	}
}
