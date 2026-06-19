// Package fetch resolves a scan target — either a local directory or a remote
// GitHub-style repo reference — to a local path on disk that bundle.Discover
// can walk. Remote refs are shallow-cloned to a temp dir; the caller cleans up
// via the returned Cleanup func.
package fetch

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// Target is a resolved scan target: a local path plus a cleanup hook (a no-op
// for local dirs, a temp-dir remove for clones).
type Target struct {
	// Path is the local directory to scan.
	Path string
	// Source is the original, human-readable target string (for the report).
	Source string
	// Remote is true if Path is a freshly cloned temp dir.
	Remote  bool
	cleanup func()
}

// Cleanup removes any temp clone. Safe to call on a local-dir target.
func (t *Target) Cleanup() {
	if t.cleanup != nil {
		t.cleanup()
	}
}

// repoRef matches host/owner/repo style refs (github.com/owner/repo,
// gitlab.com/owner/repo), with or without a scheme or trailing .git.
var repoRef = regexp.MustCompile(`^(https?://)?(www\.)?(github\.com|gitlab\.com|bitbucket\.org)/[^/]+/[^/]+/?$`)

// IsRemote reports whether target looks like a remote repo reference rather
// than a local path.
func IsRemote(target string) bool {
	if strings.HasPrefix(target, ".") || strings.HasPrefix(target, "/") || strings.HasPrefix(target, "~") {
		return false
	}
	return repoRef.MatchString(target)
}

// Resolve turns a target string into a Target. Local dirs are returned as-is;
// remote refs are shallow-cloned (git clone --depth 1) to a temp dir.
func Resolve(ctx context.Context, target string) (*Target, error) {
	if !IsRemote(target) {
		if _, err := os.Stat(target); err != nil {
			return nil, fmt.Errorf("local path %q: %w", target, err)
		}
		return &Target{Path: target, Source: target, Remote: false}, nil
	}
	return cloneRemote(ctx, target)
}

func cloneRemote(ctx context.Context, target string) (*Target, error) {
	url := normalizeURL(target)

	tmp, err := os.MkdirTemp("", "skvet-clone-")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}

	// 2-minute ceiling so a wedged clone never hangs the CLI.
	cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(cctx, "git", "clone", "--depth", "1", "--quiet", url, tmp)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		os.RemoveAll(tmp)
		return nil, fmt.Errorf("git clone %s: %w (is git installed and the repo public?)", url, err)
	}

	return &Target{
		Path:    tmp,
		Source:  target,
		Remote:  true,
		cleanup: func() { os.RemoveAll(tmp) },
	}, nil
}

// normalizeURL turns a github.com/owner/repo ref into a clonable https URL.
func normalizeURL(target string) string {
	t := strings.TrimSuffix(target, "/")
	if strings.HasPrefix(t, "http://") || strings.HasPrefix(t, "https://") {
		if !strings.HasSuffix(t, ".git") {
			t += ".git"
		}
		return t
	}
	if !strings.HasSuffix(t, ".git") {
		t += ".git"
	}
	return "https://" + t
}
