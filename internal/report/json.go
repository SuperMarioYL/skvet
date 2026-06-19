package report

import (
	"encoding/json"
	"io"
)

// JSON writes the scan result as indented, machine-readable JSON to w. Used by
// `skvet scan --json` so the same verdict can pipe into other tooling.
func JSON(w io.Writer, r Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(r)
}
