# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/SuperMarioYL/skvet/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/SuperMarioYL/skvet/releases/tag/v0.3.0
[0.2.0]: https://github.com/SuperMarioYL/skvet/releases/tag/v0.2.0
[0.1.0]: https://github.com/SuperMarioYL/skvet/releases/tag/v0.1.0
