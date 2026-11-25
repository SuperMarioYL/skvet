// Package bundle discovers installable agent-skill bundles inside a directory
// tree and reads their capability surface (scripts, hooks, manifests) into the
// in-memory shape the rule engine consumes.
//
// Two on-disk layouts are supported, matching what skvet meets in the wild:
//
//  1. Flat skill dir — a directory containing SKILL.md, optionally with a
//     sibling scripts/ of raw .sh/.py files. The shell surface is the script
//     bodies; there is no hooks.json.
//
//  2. Plugin dir — a directory containing .claude-plugin/ (plugin.json or
//     marketplace.json) and usually hooks/hooks.json. The shell surface is the
//     `command` fields in hooks.json plus any referenced scripts.
package bundle

import (
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/SuperMarioYL/skvet/internal/rules"
)

// skillFrontmatter is the subset of a SKILL.md YAML frontmatter skvet reads to
// identify and label a bundle.
type skillFrontmatter struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	License     string `yaml:"license"`
}

// parseFrontmatter extracts the leading `---`-fenced YAML block from a
// SKILL.md body, if present.
func parseFrontmatter(content string) (skillFrontmatter, bool) {
	var fm skillFrontmatter
	t := strings.TrimPrefix(content, "\ufeff") // strip UTF-8 BOM if present
	t = strings.TrimLeft(t, " \t\r\n")
	if !strings.HasPrefix(t, "---") {
		return fm, false
	}
	rest := strings.TrimPrefix(t, "---")
	end := strings.Index(rest, "\n---")
	if end < 0 {
		return fm, false
	}
	block := rest[:end]
	if err := yaml.Unmarshal([]byte(block), &fm); err != nil {
		return fm, false
	}
	return fm, true
}

// Runtime names the agent runtime a bundle targets.
type Runtime string

const (
	RuntimeClaudeCode Runtime = "claude_code"
	RuntimeUnknown    Runtime = "unknown"
)

// SkillBundle is one discovered installable unit and its read capability
// surface.
type SkillBundle struct {
	// Path is the bundle root relative to the scan root ("." for the root).
	Path string
	// Name is the bundle name from SKILL.md frontmatter, if any.
	Name string
	// Runtime is the detected target runtime.
	Runtime Runtime
	// Manifest is the bundle-relative path to the manifest that identified it
	// (SKILL.md / plugin.json), for display.
	Manifest string
	// Files are the already-read source files the rule engine scans.
	Files []rules.SourceFile
}

const maxFileBytes = 1 << 20 // 1 MiB cap — skip anything larger (likely a blob).

// Discover walks root and returns every skill bundle found. A bundle is rooted
// at any directory that holds a SKILL.md, a .claude-plugin/ dir, or a
// hooks/hooks.json. If root itself is a single bundle it is returned as one.
func Discover(root string) ([]SkillBundle, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, &os.PathError{Op: "discover", Path: root, Err: os.ErrInvalid}
	}

	roots, err := findBundleRoots(root)
	if err != nil {
		return nil, err
	}

	var bundles []SkillBundle
	for _, br := range roots {
		b, err := readBundle(root, br)
		if err != nil {
			return nil, err
		}
		// A bundle contributes nothing and is dropped. Only the root-as-bundle
		// fallback can produce an empty one (a real bundle root always carries
		// its marker file), and reporting it would print the "✓ pure prompt"
		// banner for content discovery never managed to read — a false-clean
		// verdict, the worst answer a pre-install scanner can give.
		if len(b.Files) == 0 {
			continue
		}
		bundles = append(bundles, b)
	}
	sort.Slice(bundles, func(i, j int) bool { return bundles[i].Path < bundles[j].Path })
	return bundles, nil
}

// findBundleRoots returns absolute dirs that are bundle roots. Nested bundles
// are supported (an "awesome-skills" repo with many skill subdirs). The walk
// enters each real directory once, so an ancestor never re-counts a child it
// already yielded.
func findBundleRoots(root string) ([]string, error) {
	var found []string
	sawScannable := false

	err := walkFollowLinks(root, func(path string, d os.DirEntry, isDir bool) (bool, error) {
		if isDir {
			if skipDirName(d.Name()) {
				return false, nil
			}
			if isBundleRoot(path) {
				found = append(found, path)
			}
			return true, nil
		}
		// Track whether ANY scannable file lives under the tree, so the
		// root-as-bundle fallback only fires when there is actually something
		// to scan — an empty dir or a dir of non-skill files must NOT be
		// reported as a fake "1 LOW pure-prompt" bundle.
		if _, scan := classify(path); scan {
			sawScannable = true
		}
		return false, nil
	})
	if err != nil {
		return nil, err
	}

	// If nothing matched but the root has scripts or scannable files, treat the
	// root itself as a single bundle so `scan ./somedir` always says something.
	// An empty / non-skill dir returns an empty list so the report honestly
	// prints "0 bundles" instead of a false-clean LOW verdict.
	if len(found) == 0 && sawScannable {
		found = append(found, root)
	}
	sort.Strings(found)
	return found, nil
}

// skipDirName reports whether a directory name is VCS / dependency clutter that
// the walk must never descend into.
func skipDirName(name string) bool {
	return name == ".git" || name == "node_modules" || name == "vendor"
}

// walkFollowLinks visits every entry under root (root itself excluded) in
// lexical order and descends *directory symlinks*, which filepath.WalkDir does
// not: it lstat's each entry, so a symlinked skill dir — a common layout
// (`ln -s ~/dotfiles/skills skills`, `plugins/foo -> ../skills/foo`) — is
// yielded as a plain file and its whole bundle goes unread, which used to print
// as a clean "pure prompt" verdict. Paths handed to visit are lexical joins of
// the walked names, so reported bundle/evidence paths keep the spelling the
// user typed; a visited-real-path set makes a symlink cycle terminate.
//
// visit returns whether to descend into (ignored for files) and an error that
// aborts the walk. Entry order matches WalkDir's (sorted by name).
func walkFollowLinks(root string, visit func(path string, d os.DirEntry, isDir bool) (bool, error)) error {
	return walkDir(root, visit, map[string]bool{})
}

func walkDir(dir string, visit func(path string, d os.DirEntry, isDir bool) (bool, error), visited map[string]bool) error {
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		real = dir
	}
	if visited[real] {
		return nil
	}
	visited[real] = true

	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		path := filepath.Join(dir, e.Name())
		isDir := e.IsDir()
		if !isDir && e.Type()&os.ModeSymlink != 0 {
			if info, serr := os.Stat(path); serr == nil && info.IsDir() {
				isDir = true
			}
		}
		descend, err := visit(path, e, isDir)
		if err != nil {
			return err
		}
		if isDir && descend {
			if err := walkDir(path, visit, visited); err != nil {
				return err
			}
		}
	}
	return nil
}

// isBundleRoot reports whether dir directly holds a bundle marker.
func isBundleRoot(dir string) bool {
	markers := []string{
		"SKILL.md",
		filepath.Join(".claude-plugin", "plugin.json"),
		filepath.Join(".claude-plugin", "marketplace.json"),
		filepath.Join("hooks", "hooks.json"),
	}
	for _, m := range markers {
		if fileExists(filepath.Join(dir, m)) {
			return true
		}
	}
	return false
}

// readBundle reads every scannable file under a bundle root into the rule
// engine's SourceFile shape.
func readBundle(scanRoot, bundleRoot string) (SkillBundle, error) {
	rel, err := filepath.Rel(scanRoot, bundleRoot)
	if err != nil {
		rel = bundleRoot
	}
	b := SkillBundle{
		Path:     filepath.ToSlash(rel),
		Runtime:  RuntimeUnknown,
		Manifest: "",
	}

	err = walkFollowLinks(bundleRoot, func(path string, d os.DirEntry, isDir bool) (bool, error) {
		if isDir {
			if skipDirName(d.Name()) {
				return false, nil
			}
			// A nested bundle root (a child dir that itself holds a SKILL.md /
			// .claude-plugin / hooks/hooks.json) is scanned as its own bundle by
			// a separate readBundle call from findBundleRoots. Stop here so the
			// child's files and findings are not folded into the parent's
			// verdict (duplicated evidence, inflated result.Bundles, and a
			// pure-prompt parent inheriting a nested child's HIGH). This
			// implements the ancestor-dedup the walk promises. The starting
			// bundleRoot itself is never visited, so it is never skipped.
			if isBundleRoot(path) {
				return false, nil
			}
			return true, nil
		}
		kind, scan := classify(path)
		if !scan {
			return false, nil
		}
		content, ok := readCapped(path)
		if !ok {
			return false, nil
		}
		frel, rerr := filepath.Rel(scanRoot, path)
		if rerr != nil {
			frel = path
		}
		frel = filepath.ToSlash(frel)

		if kind == rules.KindManifest && b.Manifest == "" {
			b.Manifest = frel
		}
		if strings.EqualFold(d.Name(), "SKILL.md") {
			b.Runtime = RuntimeClaudeCode
			if fm, ok := parseFrontmatter(content); ok && fm.Name != "" {
				b.Name = fm.Name
			}
		}
		if kind == rules.KindHooksJSON {
			b.Runtime = RuntimeClaudeCode
		}
		b.Files = append(b.Files, rules.SourceFile{Path: frel, Kind: kind, Content: content})
		return false, nil
	})
	if err != nil {
		return b, err
	}
	sort.Slice(b.Files, func(i, j int) bool { return b.Files[i].Path < b.Files[j].Path })
	return b, nil
}

// classify maps a file path to a rule-engine FileKind and whether it should be
// scanned at all.
func classify(path string) (rules.FileKind, bool) {
	base := filepath.Base(path)
	ext := strings.ToLower(filepath.Ext(path))

	switch {
	case strings.EqualFold(base, "hooks.json"):
		return rules.KindHooksJSON, true
	case strings.EqualFold(base, "SKILL.md"):
		return rules.KindManifest, true
	case strings.EqualFold(base, "plugin.json"), strings.EqualFold(base, "marketplace.json"),
		strings.EqualFold(base, "skill.yaml"), strings.EqualFold(base, "skill.yml"):
		return rules.KindManifest, true
	case ext == ".sh" || ext == ".bash" || ext == ".zsh" || ext == ".py" ||
		ext == ".rb" || ext == ".pl" || ext == ".js" || ext == ".ts":
		return rules.KindScript, true
	case ext == ".md" || ext == ".markdown":
		return rules.KindMarkdown, true
	case ext == ".json" || ext == ".yaml" || ext == ".yml" || ext == ".toml" || ext == ".txt" || ext == "":
		return rules.KindOther, true
	default:
		return rules.KindOther, false
	}
}

func readCapped(path string) (string, bool) {
	info, err := os.Stat(path)
	if err != nil {
		return "", false
	}
	// A scannable file larger than the cap is PARTIALLY scanned, not silently
	// dropped: a malicious skill could otherwise defeat skvet by bloating a
	// script past 1 MiB (a huge minified/obfuscated install.sh) and getting a
	// clean LOW verdict. We scan the first maxFileBytes so a payload in the
	// prefix is still caught; patterns past the cap remain out of reach (full
	// streaming is out of scope for v0.2).
	if info.Size() > maxFileBytes {
		f, err := os.Open(path)
		if err != nil {
			return "", false
		}
		defer f.Close()
		buf := make([]byte, maxFileBytes)
		n, _ := io.ReadFull(f, buf)
		// io.ReadFull returns n == len(buf) when the file is larger; for the
		// edge case of exactly-maxFileBytes-after-stat-race, n is still the
		// readable prefix, which is strictly better than skipping.
		return string(buf[:n]), true
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	return string(data), true
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
