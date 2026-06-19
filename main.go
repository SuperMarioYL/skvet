// Command skvet scans untrusted agent-skill bundles and reports a
// stars-orthogonal install-risk score.
package main

import (
	"fmt"
	"os"

	"github.com/SuperMarioYL/skvet/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "skvet: "+err.Error())
		os.Exit(1)
	}
}
