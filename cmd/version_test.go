package cmd

import (
	"encoding/json"
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

// TestChangelogLinkAppendixCoversCurrentVersion guards the two changelog
// surfaces v0.9.0 left unguarded: the link appendix and the Unreleased compare
// base. They had already drifted — [0.9.0] and [0.8.0] headings had no link
// definition (GitHub renders them as plain text) and [Unreleased] still
// compared v0.7.0...HEAD two releases later, while TestVersionLockstep passed
// because the heading itself existed.
func TestChangelogLinkAppendixCoversCurrentVersion(t *testing.T) {
	fileVer := versionFileVersion(t)
	data, err := os.ReadFile("../CHANGELOG.md")
	if err != nil {
		t.Fatalf("read CHANGELOG.md: %v", err)
	}

	// Every released section must have a matching append-only link definition,
	// or the heading renders unresolved on GitHub.
	for _, section := range changelogSections(string(data)) {
		if !strings.Contains(string(data), "\n["+section+"]: https://github.com/SuperMarioYL/skvet/") {
			t.Errorf("CHANGELOG.md section [%s] has no link definition — add `[%s]: https://github.com/SuperMarioYL/skvet/...`", section, section)
		}
	}

	if !strings.Contains(string(data), "[Unreleased]: https://github.com/SuperMarioYL/skvet/compare/v"+fileVer+"...HEAD") {
		t.Errorf("CHANGELOG.md's [Unreleased] link must compare against the current version v%s...HEAD", fileVer)
	}
}

// changelogSections returns the version labels of the `## [x.y.z]` headings, in
// file order, skipping the [Unreleased] placeholder.
func changelogSections(changelog string) []string {
	var out []string
	for _, line := range strings.Split(changelog, "\n") {
		if !strings.HasPrefix(line, "## [") {
			continue
		}
		label := strings.TrimPrefix(line, "## [")
		end := strings.IndexByte(label, ']')
		if end < 0 {
			continue
		}
		label = label[:end]
		if label == "Unreleased" {
			continue
		}
		out = append(out, label)
	}
	return out
}

// TestSiteChangelogMatchesVersion guards the fourth hand-edited version
// surface: web/site.json's newest changelog card, which the Pages site renders.
// It is bumped by hand on every release and nothing checked it against VERSION.
func TestSiteChangelogMatchesVersion(t *testing.T) {
	fileVer := versionFileVersion(t)
	data, err := os.ReadFile("../web/site.json")
	if err != nil {
		t.Fatalf("read web/site.json: %v", err)
	}
	var site struct {
		Changelog []struct {
			Version string `json:"version"`
		} `json:"changelog"`
	}
	if err := json.Unmarshal(data, &site); err != nil {
		t.Fatalf("parse web/site.json: %v", err)
	}
	if len(site.Changelog) == 0 {
		t.Fatal("web/site.json has no changelog entries")
	}
	if got := site.Changelog[0].Version; got != fileVer {
		t.Fatalf("version drift: web/site.json's newest changelog entry is %q but VERSION says %q — bump both together", got, fileVer)
	}
}

func versionFileVersion(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("../VERSION")
	if err != nil {
		t.Fatalf("read VERSION: %v", err)
	}
	v := strings.TrimSpace(string(data))
	if v == "" {
		t.Fatal("VERSION file is empty")
	}
	return v
}
