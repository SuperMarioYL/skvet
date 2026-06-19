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
			return runScan(cmd, args[0], jsonOut)
		},
		Example: `  skvet scan ./testdata/fixtures/malicious-skill
  skvet scan github.com/owner/awesome-skills
  skvet scan github.com/owner/awesome-skills --json`,
	}

	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit machine-readable JSON instead of the table")
	return cmd
}

func runScan(cmd *cobra.Command, target string, jsonOut bool) error {
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

	// Non-zero exit on HIGH so skvet is usable as a CI/pre-install gate, while
	// still printing the full report first.
	if result.Overall == score.LevelHigh {
		// Signal risk without cobra re-printing usage.
		cmd.SilenceUsage = true
		os.Exit(2)
	}
	return nil
}
