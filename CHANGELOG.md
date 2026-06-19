# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/SuperMarioYL/skvet/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/SuperMarioYL/skvet/releases/tag/v0.1.0
