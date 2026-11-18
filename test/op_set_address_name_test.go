package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The four route-G setters must reject a caller's incomplete job before any
// Ghidra call: the error names the op and the missing field, so classify() files
// it as bad_arg (the user's mistake), not as a decompiler/tool failure.
//
// The gate is stubbed to report Ghidra present and the job points at a native
// file, so the op proceeds past ghidraGate into its own validation instead of
// stopping at a "no decompiler"/"install Ghidra" skip.
func TestSetOpsRejectIncompleteJobs(t *testing.T) {
	old := ghidraFinder
	t.Cleanup(func() { ghidraFinder = old })
	ghidraFinder = func() (string, string, error) { return "/fake/analyzeHeadless", "/fake/project", nil }

	for _, c := range []struct {
		op, job, want string
		kind          errorKind
	}{
		{"set_address_name", `{"file":"/bin/ls","address":"0x1400"}`, `set_address_name: job needs "address" and "name"`, kindNeedsArg},
		{"set_addresses_names", `{"file":"/bin/ls","labels":[{"address":"0x1400"}]}`, "set_addresses_names: labels[0] is not a pair of address and name", kindBadArg},
		{"set_comment", `{"file":"/bin/ls","address":"0x1400"}`, `set_comment: job needs "address" and "text"`, kindNeedsArg},
		{"set_inline_comment", `{"file":"/bin/ls","address":"0x1400"}`, `set_inline_comment: job needs "address" and "text"`, kindNeedsArg},
	} {
		t.Run(c.op, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "job.json")
			if err := os.WriteFile(p, []byte(c.job), 0o644); err != nil {
				t.Fatal(err)
			}
			_, err := runOp(c.op, p)
			if err == nil {
				t.Fatalf("%s on %s: want an error, got none", c.op, c.job)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("%s error = %q, want it to contain %q", c.op, err, c.want)
			}
			if got := classify(err.Error()); got != c.kind {
				t.Fatalf("%s kind = %s, want %s (%v)", c.op, got, c.kind, err)
			}
		})
	}
}
