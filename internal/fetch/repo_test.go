package fetch

import (
	"context"
	"testing"
)

func TestIsRemote(t *testing.T) {
	cases := map[string]bool{
		"github.com/owner/repo":          true,
		"https://github.com/owner/repo":  true,
		"gitlab.com/owner/repo":          true,
		"github.com/owner/repo.git":      true, // a .git suffix is a valid remote ref
		"./local/dir":                    false,
		"/abs/path":                      false,
		"~/skills":                       false,
		"not-a-repo":                     false,
		"github.com/owner/repo/sub/path": false,
	}
	for in, want := range cases {
		if got := IsRemote(in); got != want {
			t.Errorf("IsRemote(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestNormalizeURL(t *testing.T) {
	cases := map[string]string{
		"github.com/o/r":         "https://github.com/o/r.git",
		"github.com/o/r/":        "https://github.com/o/r.git",
		"https://github.com/o/r": "https://github.com/o/r.git",
	}
	for in, want := range cases {
		if got := normalizeURL(in); got != want {
			t.Errorf("normalizeURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestResolve_LocalDir(t *testing.T) {
	dir := t.TempDir()
	tgt, err := Resolve(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer tgt.Cleanup()
	if tgt.Remote {
		t.Error("local dir must not be marked remote")
	}
	if tgt.Path != dir {
		t.Errorf("expected path %q, got %q", dir, tgt.Path)
	}
}

func TestResolve_MissingLocalPath(t *testing.T) {
	if _, err := Resolve(context.Background(), "./does-not-exist-xyz"); err == nil {
		t.Fatal("expected error for missing local path")
	}
}
