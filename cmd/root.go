// Package cmd wires the cobra CLI for skvet.
package cmd

import (
	"github.com/spf13/cobra"
)

// version is overridable at build time via -ldflags "-X .../cmd.version=…".
var version = "0.2.0"

// NewRootCmd builds the root `skvet` command.
func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "skvet",
		Short: "Pre-install risk scanner for agent-skill bundles",
		Long: `skvet statically scans untrusted, trending agent-skill / coding-agent
bundles and prints a stars-orthogonal install-risk score.

Skill bundles can run arbitrary shell and hooks the moment you install them;
star count is gameable and tells you nothing about what a bundle does to your
machine. skvet inspects the capability surface — shell exec, lifecycle hooks,
outbound network — and reports LOW / MEDIUM / HIGH so you decide before you
install.`,
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newScanCmd())
	return root
}

// Execute runs the root command.
func Execute() error {
	return NewRootCmd().Execute()
}
