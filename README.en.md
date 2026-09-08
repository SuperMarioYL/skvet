[简体中文](./README.md) · [Website](https://skvet.lei6393.com) · [GitHub](https://github.com/SuperMarioYL/skvet)

<picture>
  <source media="(max-width: 600px) and (prefers-color-scheme: dark)" srcset="./assets/presentation/hero-mobile-dark.svg">
  <source media="(max-width: 600px)" srcset="./assets/presentation/hero-mobile-light.svg">
  <source media="(prefers-color-scheme: dark)" srcset="./assets/presentation/hero-dark.svg">
  <img src="./assets/presentation/hero-light.svg" width="960" alt="Hero diagram">
</picture>

# skvet

**Inspect a skill before it can run**

skvet scans agent skill directories for executable scripts, lifecycle hooks and outbound network patterns, then reports source evidence and a configurable risk verdict.

## Why use it

A skill is more than its Markdown instructions: installers and hooks may run commands too. Before installing a bundle, read a report that points to the specific file, line and rule behind each finding.

- **Read exact evidence** — Each finding identifies its rule, severity, surface and source location.
- **Scan without executing** — Rules examine files in memory; the local scan does not run bundle hooks.
- **Set the CI threshold** — Use --fail-on to choose which risk levels return exit code 2.

## Architecture

<picture>
  <source media="(max-width: 600px) and (prefers-color-scheme: dark)" srcset="./assets/presentation/architecture-mobile-dark.svg">
  <source media="(max-width: 600px)" srcset="./assets/presentation/architecture-mobile-light.svg">
  <source media="(prefers-color-scheme: dark)" srcset="./assets/presentation/architecture-dark.svg">
  <img src="./assets/presentation/architecture-light.svg" width="960" alt="Architecture diagram">
</picture>

The fetch layer accepts a directory or shallow-clones a GitHub reference. Discovery identifies SKILL.md and supported plugin/hook layouts. Pure shell, hook and network rules produce findings; scoring sorts them and selects the overall level. Text and JSON renderers expose the same result.

| Component | Responsibility |
| --- | --- |
| `Target` | local path or GitHub ref |
| `Discovery` | skill and hook layouts |
| `Rules` | shell / hooks / network |
| `Score + report` | findings and exit threshold |

## Install and quickstart

Go 1.24+; Python 3 for the two-fixture demonstration.

```bash
git clone https://github.com/SuperMarioYL/skvet.git
cd skvet
go build -o bin/skvet .
```

The example scans the repository’s benign and malicious fixtures and reports their actual verdicts and exit codes. Those intentionally suspicious scripts are read only.

```bash
python3 examples/presentation_demo.py
```

## Recorded demo

<picture>
  <source media="(max-width: 600px) and (prefers-color-scheme: dark)" srcset="./assets/presentation/process-mobile-dark.svg">
  <source media="(max-width: 600px)" srcset="./assets/presentation/process-mobile-light.svg">
  <source media="(prefers-color-scheme: dark)" srcset="./assets/presentation/process-dark.svg">
  <img src="./assets/presentation/process-light.svg" width="960" alt="Process diagram">
</picture>

Bundled fixtures demonstrate both passing and blocking CI outcomes without running their scripts.

```text
benign-skill: overall=LOW exit=0
  score=0 rules=
malicious-skill: overall=HIGH exit=2
  score=100 rules=SK-HOOK-001,SK-NET-001,SK-SHELL-001,SK-SHELL-002
Scope: static fixture analysis; no hooks, scripts or network calls executed.
```

The complete command and output are recorded in [docs/demo-results.json](./docs/demo-results.json). Inputs and reproduction code are included in the repository.

![Existing terminal recording](./assets/demo.gif)

The existing recording is retained for context; the text example above documents the reproducible scenario.

## Usage

scan accepts one target. Local paths work offline; a github.com/owner/repo target requires git and network access. --json preserves detailed evidence, while --fail-on none prints a report without a risk-related failure exit. The last command above intentionally returns 2.

```bash
./bin/skvet scan ./testdata/fixtures/benign-skill
./bin/skvet scan ./testdata/fixtures/malicious-skill --json --fail-on none
./bin/skvet scan ./testdata/fixtures/malicious-skill --fail-on medium
```

## Configuration

--fail-on accepts none, low, medium or high (default high). The score is capped at 100; high-severity findings independently produce HIGH. An empty target with no discovered bundles reports NONE. Rules inspect shell, supported hook manifests and network patterns; source-backed findings matter more than treating the score as a probability.

## Integrations and responsibilities

<picture>
  <source media="(max-width: 600px) and (prefers-color-scheme: dark)" srcset="./assets/presentation/integrations-mobile-dark.svg">
  <source media="(max-width: 600px)" srcset="./assets/presentation/integrations-mobile-light.svg">
  <source media="(prefers-color-scheme: dark)" srcset="./assets/presentation/integrations-dark.svg">
  <img src="./assets/presentation/integrations-light.svg" width="960" alt="Integrations diagram">
</picture>

skvet analyzes the bundle itself. Dependency vulnerability tools, runtime sandboxes and signature verification address other parts of installation risk. Use its findings as review input and use --json when another tool needs the full result.

| Route | Implemented role |
| --- | --- |
| Local directory | scan an existing checkout |
| GitHub reference | temporary shallow clone |
| Text report | file and line evidence |
| JSON report | automation and CI gates |

## Limits and next steps

- Static pattern matching can miss behavior and can flag legitimate commands. LOW is not a guarantee that a bundle is safe.
- Remote scanning downloads a repository; it does not install the bundle.
- The recorded result covers shipped fixtures, not arbitrary runtime behavior or a complete security audit.

Implemented: local/remote targets, source evidence, text/JSON reporting and configurable exit thresholds. Future directions include more filesystem/credential patterns, additional manifest layouts and a dedicated GitHub Action wrapper. No hosted dashboard or automatic quarantine is implemented.

## License and contributions

See [LICENSE](./LICENSE). When reporting an issue, include a minimal input, the command, and the observed output.
