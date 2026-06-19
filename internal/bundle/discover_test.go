package bundle

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/SuperMarioYL/skvet/internal/rules"
)

// writeFile is a tiny helper for building fixtures on disk in a temp dir.
func writeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDiscover_FlatSkillWithScripts(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "myskill/SKILL.md", "---\nname: myskill\n---\n# doc\n")
	writeFile(t, root, "myskill/scripts/run.sh", "#!/bin/sh\necho hi\n")

	bundles, err := Discover(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(bundles) != 1 {
		t.Fatalf("expected 1 bundle, got %d: %+v", len(bundles), bundles)
	}
	b := bundles[0]
	if b.Runtime != RuntimeClaudeCode {
		t.Fatalf("SKILL.md should mark claude_code runtime, got %s", b.Runtime)
	}

	var sawScript, sawManifest bool
	for _, f := range b.Files {
		if f.Kind == rules.KindScript {
			sawScript = true
		}
		if f.Kind == rules.KindManifest {
			sawManifest = true
		}
	}
	if !sawScript {
		t.Error("flat layout: scripts/ .sh body must be read as KindScript")
	}
	if !sawManifest {
		t.Error("flat layout: SKILL.md must be read as KindManifest")
	}
}

func TestDiscover_PluginLayoutWithHooks(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "plug/.claude-plugin/plugin.json", `{"name":"plug","version":"1.0.0"}`)
	writeFile(t, root, "plug/hooks/hooks.json", `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"bash x.sh"}]}]}}`)

	bundles, err := Discover(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(bundles) != 1 {
		t.Fatalf("expected 1 plugin bundle, got %d", len(bundles))
	}

	var sawHooks bool
	for _, f := range bundles[0].Files {
		if f.Kind == rules.KindHooksJSON {
			sawHooks = true
		}
	}
	if !sawHooks {
		t.Error("plugin layout: hooks/hooks.json must be read as KindHooksJSON")
	}
}

func TestDiscover_MultipleBundles(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "a/SKILL.md", "# a\n")
	writeFile(t, root, "b/SKILL.md", "# b\n")
	writeFile(t, root, "README.md", "top-level readme, not a bundle\n")

	bundles, err := Discover(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(bundles) != 2 {
		t.Fatalf("expected 2 bundles, got %d: %+v", len(bundles), bundles)
	}
}

func TestDiscover_SkipsGitDir(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "s/SKILL.md", "# s\n")
	writeFile(t, root, "s/.git/config", "[core]\n")
	writeFile(t, root, "s/.git/hooks/hooks.json", `{"hooks":{}}`) // must NOT be scanned

	bundles, err := Discover(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range bundles {
		for _, f := range b.Files {
			if filepath.Base(filepath.Dir(f.Path)) == ".git" || filepath.Dir(f.Path) == "s/.git" {
				t.Fatalf("should not read files under .git: %s", f.Path)
			}
		}
	}
}

func TestDiscover_NonDirIsError(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "file.txt")
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Discover(p); err == nil {
		t.Fatal("expected error scanning a non-directory")
	}
}
