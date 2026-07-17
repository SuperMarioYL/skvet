package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/SuperMarioYL/skvet/internal/bundle"
	"github.com/SuperMarioYL/skvet/internal/fetch"
	"github.com/SuperMarioYL/skvet/internal/report"
	"github.com/SuperMarioYL/skvet/internal/rules"
	"github.com/SuperMarioYL/skvet/internal/score"
)

func newScanCmd() *cobra.Command {
	var jsonOut bool
	var failOn string

	cmd := &cobra.Command{
		Use:   "scan <path | github.com/owner/repo>",
		Short: "Scan a local dir or a remote repo for risky skill bundles",
		Long: `Scan discovers every installable skill bundle under the target, runs the
deterministic rule engine (shell exec, lifecycle hooks, outbound network), and
prints a per-bundle findings table plus an aggregate risk verdict.

A local directory is scanned in place. A github.com/owner/repo reference is
shallow-cloned (git clone --depth 1) to a temp dir, scanned, then deleted.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(cmd, args[0], jsonOut, failOn)
		},
		Example: `  skvet scan ./testdata/fixtures/malicious-skill
  skvet scan github.com/owner/awesome-skills
  skvet scan github.com/owner/awesome-skills --json
  skvet scan github.com/owner/awesome-skills --fail-on medium`,
	}

	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit machine-readable JSON instead of the table")
	// --fail-on configures the CI / pre-install gate threshold: skvet exits 2
	// when the overall level is at or above this value. Default "high" preserves
	// v0.1 behavior; "none" never exits non-zero.
	cmd.Flags().StringVar(&failOn, "fail-on", "high", "exit non-zero when overall risk is at or above this level (none|low|medium|high)")
	return cmd
}

func runScan(cmd *cobra.Command, target string, jsonOut bool, failOn string) error {
	tgt, err := fetch.Resolve(cmd.Context(), target)
	if err != nil {
		return err
	}
	defer tgt.Cleanup()

	bundles, err := bundle.Discover(tgt.Path)
	if err != nil {
		return fmt.Errorf("discover bundles: %w", err)
	}

	ruleset := rules.DefaultRules()
	result := report.Result{Source: tgt.Source, Bundles: len(bundles)}
	for _, b := range bundles {
		findings := rules.Run(ruleset, b.Files)
		v := score.Aggregate(b.Path, findings)
		v.BundleName = b.Name
		result.Verdicts = append(result.Verdicts, v)
	}
	result.Overall = score.Overall(result.Verdicts)

	out := cmd.OutOrStdout()
	if jsonOut {
		if err := report.JSON(out, result); err != nil {
			return err
		}
	} else {
		report.Text(out, result)
	}

	// Non-zero exit on a HIGH verdict so skvet is usable as a CI/pre-install
	// gate, while still printing the full report first. v0.2 generalizes the
	// hard-coded HIGH threshold to a configurable --fail-on level.
	threshold, ok := score.ParseLevel(failOn)
	if !ok {
		return fmt.Errorf("--fail-on: invalid level %q (want none|low|medium|high)", failOn)
	}
	if threshold != score.LevelNone && result.Overall.AtLeast(threshold) {
		// Signal risk without cobra re-printing usage. Call Cleanup explicitly:
		// os.Exit skips the deferred Cleanup above, which would leak the temp
		// clone of a HIGH-risk remote scan (the exact case skvet is built for).
		cmd.SilenceUsage = true
		tgt.Cleanup()
		os.Exit(2)
	}
	return nil
}
