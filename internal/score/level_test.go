package score

import "testing"

func TestParseLevel(t *testing.T) {
	cases := map[string]struct {
		level Level
		ok    bool
	}{
		"none":   {LevelNone, true},
		"NONE":   {LevelNone, true},
		"None":   {LevelNone, true},
		"low":    {LevelLow, true},
		"medium": {LevelMedium, true},
		"high":   {LevelHigh, true},
		"":       {"", false},
		"garbage": {"", false},
	}
	for in, want := range cases {
		got, ok := ParseLevel(in)
		if got != want.level || ok != want.ok {
			t.Errorf("ParseLevel(%q) = (%q,%v), want (%q,%v)", in, got, ok, want.level, want.ok)
		}
	}
}

func TestAtLeast_ThresholdGating(t *testing.T) {
	// fail-on high: only HIGH meets the threshold.
	if !LevelHigh.AtLeast(LevelHigh) {
		t.Error("HIGH must meet HIGH threshold")
	}
	if LevelMedium.AtLeast(LevelHigh) {
		t.Error("MEDIUM must NOT meet HIGH threshold")
	}
	// fail-on medium: MEDIUM and HIGH meet it; LOW does not.
	if !LevelMedium.AtLeast(LevelMedium) {
		t.Error("MEDIUM must meet MEDIUM threshold")
	}
	if LevelLow.AtLeast(LevelMedium) {
		t.Error("LOW must NOT meet MEDIUM threshold")
	}
	// fail-on low: every real level meets it (so a CI gate can fail on anything).
	if !LevelLow.AtLeast(LevelLow) {
		t.Error("LOW must meet LOW threshold")
	}
}
