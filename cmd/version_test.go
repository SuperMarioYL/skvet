package cmd

import (
	"os"
	"strings"
	"testing"
)

// TestVersionLockstep guards the three hand-edited version surfaces so a bump
// that forgets one fails `go test ./...` at the exact commit: the VERSION
// file, this package's `version` var (what `skvet --version` prints, and the
// value goreleaser can override via ldflags), and the CHANGELOG's heading for
// the same version. Before v0.8.0 nothing tied them together — every prior
// bump hand-edited each surface and a missed edit would silently ship a CLI
// whose --version lies about the release tag.
func TestVersionLockstep(t *testing.T) {
	data, err := os.ReadFile("../VERSION")
	if err != nil {
		t.Fatalf("read VERSION: %v", err)
	}
	fileVer := strings.TrimSpace(string(data))
	if fileVer == "" {
		t.Fatal("VERSION file is empty")
	}
	if fileVer != version {
		t.Fatalf("version drift: VERSION file says %q but cmd.version says %q — bump (or restore) both together", fileVer, version)
	}

	changelog, err := os.ReadFile("../CHANGELOG.md")
	if err != nil {
		t.Fatalf("read CHANGELOG.md: %v", err)
	}
	if !strings.Contains(string(changelog), "## ["+fileVer+"]") {
		t.Fatalf("CHANGELOG.md has no `## [%s]` heading — every released version needs an entry", fileVer)
	}
}
