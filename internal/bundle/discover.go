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
		bundles = append(bundles, b)
	}
	sort.Slice(bundles, func(i, j int) bool { return bundles[i].Path < bundles[j].Path })
	return bundles, nil
}

// findBundleRoots returns absolute dirs that are bundle roots. Nested bundles
// are supported (an "awesome-skills" repo with many skill subdirs), but a dir
// is not re-counted if an ancestor already claimed it as the same bundle root.
func findBundleRoots(root string) ([]string, error) {
	seen := map[string]bool{}
	var found []string

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		base := d.Name()
		// Skip VCS / dependency dirs entirely.
		if base == ".git" || base == "node_modules" || base == "vendor" {
			return filepath.SkipDir
		}
		if isBundleRoot(path) && !seen[path] {
			seen[path] = true
			found = append(found, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// If nothing matched but the root has scripts or scannable files, treat the
	// root itself as a single bundle so `scan ./somedir` always says something.
	if len(found) == 0 {
		found = append(found, root)
	}
	sort.Strings(found)
	return found, nil
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

	err = filepath.WalkDir(bundleRoot, func(path string, d os.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if d.IsDir() {
			base := d.Name()
			if base == ".git" || base == "node_modules" || base == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		kind, scan := classify(path)
		if !scan {
			return nil
		}
		content, ok := readCapped(path)
		if !ok {
			return nil
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
		return nil
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
	if err != nil || info.Size() > maxFileBytes {
		return "", false
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
